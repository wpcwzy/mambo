/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#if defined(PLUGINS_NEW) || defined(XTRACE_DECODER)

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../plugins.h"
#include "xtrace_disasm.h"
#include "xtrace_format.h"
#include "xtrace_zstd.h"

#define XTRACE_DEFAULT_FILE "pinatrace.out"
#define XTRACE_DEFAULT_BINARY_FILE "xtrace.bin"
#define XTRACE_INFO_LOAD 1
#define XTRACE_INFO_STORE 2
#define XTRACE_INFO_SIZE_SHIFT 2
#define XTRACE_INST_META_INST_BITS 24
#define XTRACE_INST_META_INST_MASK ((uintptr_t)((1u << XTRACE_INST_META_INST_BITS) - 1))
#define XTRACE_MAX_BYTE_VALUE 16
#define XTRACE_EVENTS_PER_BLOCK 32768
#define XTRACE_TIMESTAMP_SAMPLE_INTERVAL 256

#ifndef XTRACE_DECODER
struct xtrace_thread {
  uintptr_t store_addr;
  uintptr_t store_info;
  bool store_pending;
  uint32_t id;
  uint32_t event_count;
  uint64_t instruction_count;
  uintptr_t next_pc;
  bool has_next_pc;
  bool instrument_block;
  bool cached_range_valid;
  bool cached_range_selected;
  uintptr_t cached_range_start;
  uintptr_t cached_range_end;
  uint64_t cached_range_generation;
  struct xtrace_event *events;
  void *compressed;
  size_t compressed_capacity;
  ZSTD_CCtx *compression_ctx;
};

struct xtrace_function_filter {
  char *name;
  bool matched;
};

struct xtrace_function_range {
  uintptr_t start;
  uintptr_t end;
  bool selected;
};

static FILE *xtrace_file;
static bool xtrace_close_file;
static bool xtrace_ring_written;
static bool xtrace_has_base_override;
static bool xtrace_binary = true;
static bool xtrace_output_failed;
static uintptr_t xtrace_base_override;
static int xtrace_ring_level = 3;
static int xtrace_compression_level = 1;
static uint64_t xtrace_start_stamp;
static uint32_t xtrace_next_thread_id;
static uint64_t xtrace_total_events;
static uint64_t xtrace_total_raw_bytes;
static uint64_t xtrace_total_stored_bytes;
static struct xtrace_function_filter *xtrace_function_filters;
static size_t xtrace_function_filter_count;
static size_t xtrace_function_filter_capacity;
static struct xtrace_function_range *xtrace_function_ranges;
static size_t xtrace_function_range_count;
static size_t xtrace_function_range_capacity;
static uint64_t xtrace_function_range_generation;
static bool xtrace_selective_capture;
static pthread_mutex_t xtrace_output_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t xtrace_function_range_lock = PTHREAD_MUTEX_INITIALIZER;

enum xtrace_timestamp_mode {
  XTRACE_TIMESTAMP_NONE,
  XTRACE_TIMESTAMP_CLOCK,
};

static enum xtrace_timestamp_mode xtrace_timestamp_mode =
    XTRACE_TIMESTAMP_CLOCK;
static uint64_t xtrace_cpu_hz = 1600000000ull;
#endif

static void xtrace_appendf(char *buf, size_t cap, size_t *pos,
                           const char *fmt, ...) {
  if (*pos >= cap) {
    return;
  }

  va_list ap;
  va_start(ap, fmt);
  int written = vsnprintf(buf + *pos, cap - *pos, fmt, ap);
  va_end(ap);

  if (written < 0) {
    return;
  }
  if ((size_t)written >= cap - *pos) {
    *pos = cap - 1;
  } else {
    *pos += (size_t)written;
  }
}

static uint64_t xtrace_scale_timestamp(uint64_t nanoseconds,
                                       uint64_t frequency_hz) {
  __uint128_t scaled = (__uint128_t)nanoseconds * frequency_hz;
  return (uint64_t)(scaled / 1000000000ull);
}

#ifndef XTRACE_DECODER
static uint64_t xtrace_read_clock_stamp(void) {
  struct timespec ts;
#ifdef CLOCK_MONOTONIC_RAW
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#else
  clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint64_t xtrace_read_stamp(void) {
  return xtrace_read_clock_stamp();
}

static uint64_t xtrace_timestamp(void) {
  uint64_t stamp = xtrace_read_stamp();
  return stamp >= xtrace_start_stamp ? stamp - xtrace_start_stamp : stamp;
}

static uintptr_t xtrace_source_addr(mambo_context *ctx) {
  return (uintptr_t)mambo_get_source_addr(ctx) & ~(uintptr_t)1;
}

static uintptr_t xtrace_inst_encoding(mambo_context *ctx) {
  uintptr_t pc = xtrace_source_addr(ctx);
  int inst_len = mambo_get_inst_len(ctx);
  uintptr_t encoding = 0;

  if (inst_len > 0 && inst_len <= (int)sizeof(encoding)) {
    memcpy(&encoding, (void *)pc, inst_len);
  }
  return encoding;
}

static uintptr_t xtrace_inst_meta(mambo_context *ctx) {
  uintptr_t inst_type = (uintptr_t)mambo_get_inst_type(ctx) & 0xff;
  uintptr_t inst = (uintptr_t)mambo_get_inst(ctx) & XTRACE_INST_META_INST_MASK;
  return (inst_type << XTRACE_INST_META_INST_BITS) | inst;
}

static uintptr_t xtrace_inst_info(mambo_context *ctx) {
  return (xtrace_inst_meta(ctx) << 4) |
         ((uintptr_t)mambo_get_inst_len(ctx) & 0xf);
}
#endif

static int xtrace_meta_inst_type(uintptr_t meta) {
  return (int)(meta >> XTRACE_INST_META_INST_BITS);
}

static int xtrace_meta_inst(uintptr_t meta) {
  uintptr_t inst = meta & XTRACE_INST_META_INST_MASK;
  return inst == XTRACE_INST_META_INST_MASK ? -1 : (int)inst;
}

#ifndef XTRACE_DECODER
static void xtrace_add_function_filter(const char *value, size_t length) {
  while (length != 0 && isspace((unsigned char)*value)) {
    value++;
    length--;
  }
  while (length != 0 && isspace((unsigned char)value[length - 1])) {
    length--;
  }
  if (length == 0) {
    return;
  }

  for (size_t i = 0; i < xtrace_function_filter_count; i++) {
    if (strlen(xtrace_function_filters[i].name) == length &&
        strncmp(xtrace_function_filters[i].name, value, length) == 0) {
      return;
    }
  }

  if (xtrace_function_filter_count == xtrace_function_filter_capacity) {
    size_t capacity = xtrace_function_filter_capacity == 0
                          ? 8
                          : xtrace_function_filter_capacity * 2;
    void *filters = realloc(xtrace_function_filters,
                            capacity * sizeof(*xtrace_function_filters));
    if (filters == NULL) {
      fprintf(stderr, "xtrace: failed to allocate function filters\n");
      abort();
    }
    xtrace_function_filters = filters;
    xtrace_function_filter_capacity = capacity;
  }

  char *name = strndup(value, length);
  if (name == NULL) {
    fprintf(stderr, "xtrace: failed to allocate a function filter\n");
    abort();
  }
  xtrace_function_filters[xtrace_function_filter_count++] =
      (struct xtrace_function_filter){.name = name};
}

static void xtrace_parse_function_list(const char *list) {
  const char *start = list;
  for (const char *cursor = list;; cursor++) {
    if (*cursor == ',' || *cursor == '\0') {
      xtrace_add_function_filter(start, (size_t)(cursor - start));
      if (*cursor == '\0') {
        break;
      }
      start = cursor + 1;
    }
  }
}

static void xtrace_parse_function_file(const char *path) {
  FILE *file = fopen(path, "r");
  if (file == NULL) {
    fprintf(stderr, "xtrace: failed to open function file %s: %s\n", path,
            strerror(errno));
    abort();
  }

  char *line = NULL;
  size_t capacity = 0;
  while (getline(&line, &capacity, file) >= 0) {
    char *content = line;
    while (isspace((unsigned char)*content)) {
      content++;
    }
    if (*content != '\0' && *content != '#') {
      xtrace_parse_function_list(content);
    }
  }
  if (ferror(file)) {
    fprintf(stderr, "xtrace: failed to read function file %s: %s\n", path,
            strerror(errno));
    free(line);
    fclose(file);
    abort();
  }
  free(line);
  fclose(file);
}

static int xtrace_compare_function_filters(const void *left,
                                           const void *right) {
  const struct xtrace_function_filter *left_filter = left;
  const struct xtrace_function_filter *right_filter = right;
  return strcmp(left_filter->name, right_filter->name);
}

static void xtrace_parse_config(void) {
  const char *functions = getenv("MAMBO_XTRACE_FUNCTIONS");
  const char *function_file = getenv("MAMBO_XTRACE_FUNCTION_FILE");
  xtrace_selective_capture = functions != NULL || function_file != NULL;
  if (functions != NULL && functions[0] != '\0') {
    xtrace_parse_function_list(functions);
  }
  if (function_file != NULL && function_file[0] != '\0') {
    xtrace_parse_function_file(function_file);
  }
  if (xtrace_selective_capture && xtrace_function_filter_count == 0) {
    fprintf(stderr, "xtrace: selective capture has no function names\n");
    abort();
  }
  if (xtrace_function_filter_count > 1) {
    qsort(xtrace_function_filters, xtrace_function_filter_count,
          sizeof(*xtrace_function_filters), xtrace_compare_function_filters);
  }

  const char *ring = getenv("MAMBO_XTRACE_RING");
  if (ring != NULL && ring[0] != '\0') {
    xtrace_ring_level = atoi(ring);
  }

  const char *base = getenv("MAMBO_XTRACE_BASE");
  if (base != NULL && base[0] != '\0') {
    xtrace_base_override = (uintptr_t)strtoull(base, NULL, 0);
    xtrace_has_base_override = true;
  }

  const char *format = getenv("MAMBO_XTRACE_FORMAT");
  if (format != NULL && strcmp(format, "text") == 0) {
    xtrace_binary = false;
  } else if (format != NULL && strcmp(format, "binary") != 0) {
    fprintf(stderr, "xtrace: unknown format '%s'; using binary\n", format);
  }

  const char *cpu_hz = getenv("MAMBO_XTRACE_CPU_HZ");
  if (cpu_hz != NULL && cpu_hz[0] != '\0') {
    xtrace_cpu_hz = strtoull(cpu_hz, NULL, 0);
  }

  const char *timestamps = getenv("MAMBO_XTRACE_TIMESTAMPS");
  if (timestamps != NULL && timestamps[0] != '\0') {
    if (strcmp(timestamps, "none") == 0 ||
        strcmp(timestamps, "logical") == 0) {
      xtrace_timestamp_mode = XTRACE_TIMESTAMP_NONE;
    } else if (strcmp(timestamps, "clock") == 0) {
      xtrace_timestamp_mode = XTRACE_TIMESTAMP_CLOCK;
    } else if (strcmp(timestamps, "ipc") == 0) {
      if (xtrace_cpu_hz == 0) {
        fprintf(stderr,
                "xtrace: ipc timestamps require MAMBO_XTRACE_CPU_HZ\n");
        abort();
      }
      xtrace_timestamp_mode = XTRACE_TIMESTAMP_CLOCK;
    } else if (strcmp(timestamps, "cycle") == 0) {
      fprintf(stderr,
              "xtrace: direct cycle counters are unsafe; use ipc with "
              "MAMBO_XTRACE_CPU_HZ\n");
      abort();
    } else {
      fprintf(stderr, "xtrace: unknown timestamp mode '%s'\n", timestamps);
    }
  }
  if (xtrace_timestamp_mode == XTRACE_TIMESTAMP_CLOCK && xtrace_cpu_hz == 0) {
    fprintf(stderr,
            "xtrace: clock timestamps require a nonzero MAMBO_XTRACE_CPU_HZ\n");
    abort();
  }

  const char *level = getenv("MAMBO_XTRACE_COMPRESSION_LEVEL");
  if (level != NULL && level[0] != '\0') {
    xtrace_compression_level = atoi(level);
  }
}

static struct xtrace_function_filter *xtrace_find_function_filter(
    const char *name) {
  size_t low = 0;
  size_t high = xtrace_function_filter_count;
  while (low < high) {
    size_t middle = low + (high - low) / 2;
    int comparison = strcmp(name, xtrace_function_filters[middle].name);
    if (comparison == 0) {
      return &xtrace_function_filters[middle];
    }
    if (comparison < 0) {
      high = middle;
    } else {
      low = middle + 1;
    }
  }
  return NULL;
}

static ssize_t xtrace_find_function_range(uintptr_t pc) {
  size_t low = 0;
  size_t high = xtrace_function_range_count;
  while (low < high) {
    size_t middle = low + (high - low) / 2;
    if (xtrace_function_ranges[middle].start <= pc) {
      low = middle + 1;
    } else {
      high = middle;
    }
  }

  if (low != 0 && pc < xtrace_function_ranges[low - 1].end) {
    return (ssize_t)(low - 1);
  }
  return -1;
}

static void xtrace_add_function_range(uintptr_t start, uintptr_t end,
                                      bool selected) {
  size_t low = 0;
  size_t high = xtrace_function_range_count;
  while (low < high) {
    size_t middle = low + (high - low) / 2;
    if (xtrace_function_ranges[middle].start < start) {
      low = middle + 1;
    } else {
      high = middle;
    }
  }

  if (low < xtrace_function_range_count &&
      xtrace_function_ranges[low].start == start &&
      xtrace_function_ranges[low].end == end) {
    xtrace_function_ranges[low].selected = selected;
    return;
  }

  if (xtrace_function_range_count == xtrace_function_range_capacity) {
    size_t capacity = xtrace_function_range_capacity == 0
                          ? 64
                          : xtrace_function_range_capacity * 2;
    void *ranges = realloc(xtrace_function_ranges,
                           capacity * sizeof(*xtrace_function_ranges));
    if (ranges == NULL) {
      fprintf(stderr, "xtrace: failed to allocate function range cache\n");
      abort();
    }
    xtrace_function_ranges = ranges;
    xtrace_function_range_capacity = capacity;
  }

  memmove(&xtrace_function_ranges[low + 1],
          &xtrace_function_ranges[low],
          (xtrace_function_range_count - low) *
              sizeof(*xtrace_function_ranges));
  xtrace_function_ranges[low] = (struct xtrace_function_range){
      .start = start,
      .end = end,
      .selected = selected,
  };
  xtrace_function_range_count++;
}

static bool xtrace_should_instrument(struct xtrace_thread *thread,
                                     uintptr_t pc) {
  if (!xtrace_selective_capture) {
    return true;
  }

  uint64_t generation = __atomic_load_n(&xtrace_function_range_generation,
                                         __ATOMIC_ACQUIRE);
  if (thread->cached_range_valid &&
      thread->cached_range_generation == generation &&
      pc >= thread->cached_range_start && pc < thread->cached_range_end) {
    return thread->cached_range_selected;
  }

  int ret = pthread_mutex_lock(&xtrace_function_range_lock);
  assert(ret == 0);
  generation = __atomic_load_n(&xtrace_function_range_generation,
                               __ATOMIC_ACQUIRE);

  ssize_t range_index = xtrace_find_function_range(pc);
  if (range_index >= 0) {
    struct xtrace_function_range range =
        xtrace_function_ranges[range_index];
    thread->cached_range_valid = true;
    thread->cached_range_selected = range.selected;
    thread->cached_range_start = range.start;
    thread->cached_range_end = range.end;
    thread->cached_range_generation = generation;
    ret = pthread_mutex_unlock(&xtrace_function_range_lock);
    assert(ret == 0);
    return range.selected;
  }

  char *symbol = NULL;
  void *symbol_start = NULL;
  size_t symbol_size = 0;
  if (get_symbol_info_by_addr_with_size(pc, &symbol, &symbol_start,
                                        &symbol_size, NULL) != 0 ||
      symbol == NULL || symbol_start == NULL || symbol_size == 0) {
    free(symbol);
    ret = pthread_mutex_unlock(&xtrace_function_range_lock);
    assert(ret == 0);
    thread->cached_range_valid = false;
    return false;
  }

  struct xtrace_function_filter *filter =
      xtrace_find_function_filter(symbol);
  bool selected = filter != NULL;
  if (selected) {
    __atomic_store_n(&filter->matched, true, __ATOMIC_RELAXED);
  }
  free(symbol);

  uintptr_t start = (uintptr_t)symbol_start;
  uintptr_t end = symbol_size > UINTPTR_MAX - start
                      ? UINTPTR_MAX
                      : start + symbol_size;
  xtrace_add_function_range(start, end, selected);
  thread->cached_range_valid = true;
  thread->cached_range_selected = selected;
  thread->cached_range_start = start;
  thread->cached_range_end = end;
  thread->cached_range_generation = generation;

  ret = pthread_mutex_unlock(&xtrace_function_range_lock);
  assert(ret == 0);
  return selected;
}

static int xtrace_vm_op_handler(mambo_context *ctx) {
  if (!xtrace_selective_capture) {
    return 0;
  }

  uintptr_t start = (uintptr_t)mambo_get_vm_addr(ctx);
  size_t size = mambo_get_vm_size(ctx);
  uintptr_t end = size > UINTPTR_MAX - start ? UINTPTR_MAX : start + size;

  int ret = pthread_mutex_lock(&xtrace_function_range_lock);
  assert(ret == 0);
  size_t write = 0;
  for (size_t read = 0; read < xtrace_function_range_count; read++) {
    struct xtrace_function_range range = xtrace_function_ranges[read];
    if (range.start < end && range.end > start) {
      continue;
    }
    xtrace_function_ranges[write++] = range;
  }
  bool invalidated = write != xtrace_function_range_count;
  xtrace_function_range_count = write;
  if (invalidated) {
    __atomic_add_fetch(&xtrace_function_range_generation, 1,
                       __ATOMIC_RELEASE);
  }
  ret = pthread_mutex_unlock(&xtrace_function_range_lock);
  assert(ret == 0);
  return 0;
}

static void xtrace_open_file(void) {
  const char *path = getenv("MAMBO_XTRACE_FILE");
  if (path == NULL || path[0] == '\0') {
    path = xtrace_binary ? XTRACE_DEFAULT_BINARY_FILE : XTRACE_DEFAULT_FILE;
  }

  if (strcmp(path, "-") == 0) {
    xtrace_file = xtrace_binary ? stdout : stderr;
    xtrace_close_file = false;
  } else {
    xtrace_file = fopen(path, xtrace_binary ? "wb" : "w");
    xtrace_close_file = true;
  }

  if (xtrace_file == NULL) {
    fprintf(stderr, "xtrace: failed to open %s: %s\n", path,
            strerror(errno));
    if (xtrace_binary) {
      abort();
    }
    fprintf(stderr, "xtrace: falling back to stderr\n");
    xtrace_file = stderr;
    xtrace_close_file = false;
  }

  setvbuf(xtrace_file, NULL, _IOFBF, 1 << 20);
}

static void xtrace_print_ring_line(uintptr_t pc, bool discontinuity) {
  bool first_ring = !xtrace_ring_written;
  if (!first_ring && !discontinuity) {
    return;
  }

  uintptr_t target = first_ring && xtrace_has_base_override
                         ? xtrace_base_override
                         : pc;
  fprintf(xtrace_file, "ring %d, pc -> %" PRIxPTR "\n",
          xtrace_ring_level, target);
  xtrace_ring_written = true;
}
#endif

static void xtrace_format_bytes(char *buf, size_t cap, size_t *pos,
                                uintptr_t encoding, uintptr_t inst_len) {
  if (inst_len == 0 || inst_len > sizeof(encoding)) {
    xtrace_appendf(buf, cap, pos, "??");
    return;
  }

  for (uintptr_t i = 0; i < inst_len; i++) {
    xtrace_appendf(buf, cap, pos, "%02" PRIxPTR,
                   (encoding >> (i * 8)) & 0xff);
  }
}

#ifndef XTRACE_DECODER
static void xtrace_print_mem_value(uintptr_t addr, uintptr_t size) {
  if (size == 0) {
    fprintf(xtrace_file, "?");
  } else if (size <= sizeof(uint64_t)) {
    uint64_t value = 0;
    memcpy(&value, (void *)addr, size);
    fprintf(xtrace_file, "%" PRIx64, value);
  } else {
    unsigned char bytes[XTRACE_MAX_BYTE_VALUE];
    uintptr_t bytes_to_print = size;
    if (bytes_to_print > XTRACE_MAX_BYTE_VALUE) {
      bytes_to_print = XTRACE_MAX_BYTE_VALUE;
    }

    memcpy(bytes, (void *)addr, bytes_to_print);
    for (uintptr_t i = 0; i < bytes_to_print; i++) {
      fprintf(xtrace_file, "%02x", bytes[i]);
    }
    if (bytes_to_print < size) {
      fprintf(xtrace_file, "...");
    }
  }
}
#endif

#ifdef __aarch64__
static const char *xtrace_a64_base_reg(unsigned int reg) {
  static const char *const names[] = {
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
    "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp"
  };
  return reg < 32 ? names[reg] : "x?";
}

static const char *xtrace_a64_gpr(unsigned int reg, bool wide) {
  static const char *const xnames[] = {
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
    "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "x29", "x30", "xzr"
  };
  static const char *const wnames[] = {
    "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7",
    "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15",
    "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
    "w24", "w25", "w26", "w27", "w28", "w29", "w30", "wzr"
  };
  if (reg >= 32) {
    return wide ? "x?" : "w?";
  }
  return wide ? xnames[reg] : wnames[reg];
}

static const char *xtrace_a64_vec(unsigned int reg) {
  static const char *const names[] = {
    "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
    "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
    "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
    "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"
  };
  return reg < 32 ? names[reg] : "v?";
}

static bool xtrace_a64_encoding_is_load(uintptr_t encoding) {
  return (encoding & (1u << 22)) != 0;
}

static bool xtrace_a64_ldr_str_is_load(uintptr_t encoding) {
  return ((encoding >> 22) & 3) != 0;
}

static const char *xtrace_a64_mnemonic(int inst, uintptr_t encoding) {
  switch ((a64_instruction)inst) {
    case A64_LDR_LIT:
      return "ldr";
    case A64_LDR_STR_IMMED:
    case A64_LDR_STR_REG:
    case A64_LDR_STR_UNSIGNED_IMMED:
      return xtrace_a64_ldr_str_is_load(encoding) ? "ldr" : "str";
    case A64_LDP_STP:
      return xtrace_a64_encoding_is_load(encoding) ? "ldp" : "stp";
    case A64_LDX_STX:
      return xtrace_a64_encoding_is_load(encoding) ? "ldxr" : "stxr";
    case A64_LDX_STX_MULTIPLE:
    case A64_LDX_STX_MULTIPLE_POST:
    case A64_LDX_STX_SINGLE:
    case A64_LDX_STX_SINGLE_POST:
      return xtrace_a64_encoding_is_load(encoding) ? "ld1" : "st1";
    case A64_LDADD:
      return "ldadd";
    case A64_LDCLR:
      return "ldclr";
    case A64_LDEOR:
      return "ldeor";
    case A64_LDSET:
      return "ldset";
    case A64_SWP:
      return "swp";
    default:
      return xtrace_a64_name((a64_instruction)inst);
  }
}

static const char *xtrace_a64_access_reg(unsigned int reg, unsigned int size,
                                         unsigned int v) {
  if (v != 0) {
    return xtrace_a64_vec(reg);
  }
  return xtrace_a64_gpr(reg, size == 3);
}

static void xtrace_append_a64_operands(char *buf, size_t cap, size_t *pos,
                                       uintptr_t pc, uintptr_t encoding,
                                       int inst) {
  (void)encoding;
  switch ((a64_instruction)inst) {
    case A64_LDR_LIT: {
      unsigned int opc, v, imm19, rt;
      a64_LDR_lit_decode_fields((uint32_t *)pc, &opc, &v, &imm19, &rt);
      int64_t offset = (int64_t)sign_extend64(19, imm19) << 2;
      xtrace_appendf(buf, cap, pos, " %s, [pc, #%" PRId64 "]",
                     v ? xtrace_a64_vec(rt) : xtrace_a64_gpr(rt, opc != 0),
                     offset);
      break;
    }
    case A64_LDR_STR_UNSIGNED_IMMED: {
      unsigned int size, v, opc, imm12, rn, rt;
      a64_LDR_STR_unsigned_immed_decode_fields((uint32_t *)pc, &size, &v,
                                               &opc, &imm12, &rn, &rt);
      unsigned int scale = ((v & (opc >> 1)) << 2) + size;
      uintptr_t offset = (uintptr_t)imm12 << scale;
      xtrace_appendf(buf, cap, pos, " %s, [%s",
                     xtrace_a64_access_reg(rt, size, v),
                     xtrace_a64_base_reg(rn));
      if (offset != 0) {
        xtrace_appendf(buf, cap, pos, ", #%" PRIuPTR, offset);
      }
      xtrace_appendf(buf, cap, pos, "]");
      break;
    }
    case A64_LDR_STR_IMMED: {
      unsigned int size, v, opc, imm9, type, rn, rt;
      a64_LDR_STR_immed_decode_fields((uint32_t *)pc, &size, &v, &opc,
                                      &imm9, &type, &rn, &rt);
      int32_t offset = sign_extend32(9, imm9);
      xtrace_appendf(buf, cap, pos, " %s, [%s",
                     xtrace_a64_access_reg(rt, size, v),
                     xtrace_a64_base_reg(rn));
      if (offset != 0) {
        xtrace_appendf(buf, cap, pos, ", #%" PRId32, offset);
      }
      xtrace_appendf(buf, cap, pos, "]%s", type == 2 ? "!" : "");
      break;
    }
    case A64_LDR_STR_REG: {
      unsigned int size, v, opc, rm, option, s, rn, rt;
      (void)opc;
      (void)option;
      a64_LDR_STR_reg_decode_fields((uint32_t *)pc, &size, &v, &opc,
                                    &rm, &option, &s, &rn, &rt);
      xtrace_appendf(buf, cap, pos, " %s, [%s, %s",
                     xtrace_a64_access_reg(rt, size, v),
                     xtrace_a64_base_reg(rn),
                     xtrace_a64_gpr(rm, true));
      if (s != 0) {
        xtrace_appendf(buf, cap, pos, ", lsl #%u", size);
      }
      xtrace_appendf(buf, cap, pos, "]");
      break;
    }
    case A64_LDP_STP: {
      unsigned int opc, v, type, l, imm7, rt2, rn, rt;
      (void)type;
      (void)l;
      a64_LDP_STP_decode_fields((uint32_t *)pc, &opc, &v, &type, &l,
                                &imm7, &rt2, &rn, &rt);
      int32_t offset = sign_extend32(7, imm7) << (2 + (opc >> (1 - v)));
      xtrace_appendf(buf, cap, pos, " %s, %s, [%s",
                     xtrace_a64_access_reg(rt, 3, v),
                     xtrace_a64_access_reg(rt2, 3, v),
                     xtrace_a64_base_reg(rn));
      if (offset != 0) {
        xtrace_appendf(buf, cap, pos, ", #%" PRId32, offset);
      }
      xtrace_appendf(buf, cap, pos, "]");
      break;
    }
    default:
      break;
  }
}
#endif

#ifdef __riscv
static const char *xtrace_riscv_reg(unsigned int reg) {
  static const char *const names[] = {
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
    "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
    "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"
  };
  return reg < 32 ? names[reg] : "x?";
}

static const char *xtrace_riscv_freg(unsigned int reg) {
  static const char *const names[] = {
    "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7",
    "fs0", "fs1", "fa0", "fa1", "fa2", "fa3", "fa4", "fa5",
    "fa6", "fa7", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7",
    "fs8", "fs9", "fs10", "fs11", "ft8", "ft9", "ft10", "ft11"
  };
  return reg < 32 ? names[reg] : "f?";
}

static const char *xtrace_riscv_rm(unsigned int rm) {
  static const char *const names[] = {
    "rne", "rtz", "rdn", "rup", "rmm", "rm5", "rm6", "dyn"
  };
  return rm < 8 ? names[rm] : "rm?";
}

static void xtrace_append_riscv_aqrl(char *buf, size_t cap, size_t *pos,
                                     unsigned int aq, unsigned int rl) {
  if (aq != 0 && rl != 0) {
    xtrace_appendf(buf, cap, pos, ".aqrl");
  } else if (aq != 0) {
    xtrace_appendf(buf, cap, pos, ".aq");
  } else if (rl != 0) {
    xtrace_appendf(buf, cap, pos, ".rl");
  }
}

static void xtrace_append_riscv_fence_set(char *buf, size_t cap, size_t *pos,
                                          unsigned int bits) {
  static const char names[] = "iorw";
  bool any = false;

  for (unsigned int i = 0; i < 4; i++) {
    unsigned int bit = 1u << (3 - i);
    if ((bits & bit) != 0) {
      xtrace_appendf(buf, cap, pos, "%c", names[i]);
      any = true;
    }
  }
  if (!any) {
    xtrace_appendf(buf, cap, pos, "0");
  }
}

static unsigned int xtrace_riscv_c_addi4spn_imm(unsigned int nzuimm) {
  return (((nzuimm >> 6) & 0x3) << 4) |
         (((nzuimm >> 2) & 0xf) << 6) |
         (((nzuimm >> 1) & 0x1) << 2) |
         ((nzuimm & 0x1) << 3);
}

static int32_t xtrace_riscv_c_addi16sp_imm(unsigned int immhi,
                                           unsigned int immlo) {
  uint32_t immediate = ((immhi & 0x1) << 9) |
                       (((immlo >> 4) & 0x1) << 4) |
                       (((immlo >> 3) & 0x1) << 6) |
                       (((immlo >> 1) & 0x3) << 7) |
                       ((immlo & 0x1) << 5);
  return sign_extend32(10, immediate);
}

static unsigned int xtrace_riscv_c_word_offset(unsigned int uimmhi,
                                               unsigned int uimmlo) {
  return (uimmhi << 3) | ((uimmlo & 0x1) << 6) | ((uimmlo & 0x2) << 1);
}

static unsigned int xtrace_riscv_c_doubleword_offset(unsigned int uimmhi,
                                                     unsigned int uimmlo) {
  return (uimmhi << 3) | (uimmlo << 6);
}

static unsigned int xtrace_riscv_c_spword_load_offset(unsigned int uimmhi,
                                                      unsigned int uimmlo) {
  return (uimmhi << 5) | ((uimmlo & 0x3) << 6) | (uimmlo & 0x1c);
}

static unsigned int xtrace_riscv_c_spdoubleword_load_offset(unsigned int uimmhi,
                                                            unsigned int uimmlo) {
  return (uimmhi << 5) | ((uimmlo & 0x7) << 6) | (uimmlo & 0x18);
}

static unsigned int xtrace_riscv_c_spword_store_offset(unsigned int uimm) {
  return ((uimm & 0x3) << 6) | (uimm & 0x1c);
}

static unsigned int xtrace_riscv_c_spdoubleword_store_offset(unsigned int uimm) {
  return ((uimm & 0x7) << 6) | (uimm & 0x18);
}

static int32_t xtrace_riscv_store_offset(unsigned int immhi,
                                         unsigned int immlo) {
  return sign_extend32(12, (immhi << 5) | immlo);
}

static int32_t xtrace_riscv_branch_offset(unsigned int immhi,
                                          unsigned int immlo) {
  uint32_t immediate = (extr(4, 1, immlo) << 1) |
                       (extr(6, 0, immhi) << 5) |
                       (extr(1, 0, immlo) << 11) |
                       (extr(1, 6, immhi) << 12);
  return sign_extend32(13, immediate);
}

static int32_t xtrace_riscv_c_branch_offset(unsigned int immhi,
                                            unsigned int immlo) {
  uint32_t offset = (extr(2, 1, immlo) << 1) |
                    (extr(2, 0, immhi) << 3) |
                    (extr(1, 0, immlo) << 5) |
                    (extr(2, 3, immlo) << 6) |
                    (extr(1, 2, immhi) << 8);
  return sign_extend32(9, offset);
}

static int32_t xtrace_riscv_jal_offset(unsigned int imm) {
  uint32_t immediate = (extr(10, 9, imm) << 1) |
                       (extr(1, 8, imm) << 11) |
                       (extr(8, 0, imm) << 12) |
                       (extr(1, 19, imm) << 20);
  return sign_extend32(21, immediate);
}

static int32_t xtrace_riscv_c_j_offset(unsigned int imm) {
  uint32_t offset = (extr(3, 1, imm) << 1) |
                    (extr(1, 9, imm) << 4) |
                    (extr(1, 0, imm) << 5) |
                    (extr(1, 5, imm) << 6) |
                    (extr(1, 4, imm) << 7) |
                    (extr(2, 7, imm) << 8) |
                    (extr(1, 6, imm) << 10) |
                    (extr(1, 10, imm) << 11);
  return sign_extend32(12, offset);
}

static int32_t xtrace_riscv_c_imm(unsigned int immhi, unsigned int immlo) {
  return sign_extend32(6, (immhi << 5) | immlo);
}

static void xtrace_append_riscv_operands(char *buf, size_t cap, size_t *pos,
                                         uintptr_t pc, uintptr_t encoding,
                                         int inst) {
  switch ((riscv_instruction)inst) {
    case RISCV_C_ADDI4SPN: {
      unsigned int rd, nzuimm;
      riscv_c_addi4spn_decode_fields((uint16_t *)&encoding, &rd, &nzuimm);
      xtrace_appendf(buf, cap, pos, " %s, sp, %u",
                     xtrace_riscv_reg(rd + s0),
                     xtrace_riscv_c_addi4spn_imm(nzuimm));
      break;
    }
    case RISCV_C_FLD:
    case RISCV_C_LW:
    case RISCV_C_LD: {
      unsigned int rd, rs1, uimmhi, uimmlo;
      riscv_c_lw_decode_fields((uint16_t *)&encoding, &rd, &rs1, &uimmhi, &uimmlo);
      unsigned int offset = inst == RISCV_C_LW
                              ? xtrace_riscv_c_word_offset(uimmhi, uimmlo)
                              : xtrace_riscv_c_doubleword_offset(uimmhi, uimmlo);
      if (inst == RISCV_C_FLD) {
        xtrace_appendf(buf, cap, pos, " %s, %u(%s)",
                       xtrace_riscv_freg(rd + s0), offset,
                       xtrace_riscv_reg(rs1 + s0));
      } else {
        xtrace_appendf(buf, cap, pos, " %s, %u(%s)",
                       xtrace_riscv_reg(rd + s0), offset,
                       xtrace_riscv_reg(rs1 + s0));
      }
      break;
    }
    case RISCV_C_FSD:
    case RISCV_C_SW:
    case RISCV_C_SD: {
      unsigned int rs2, rs1, uimmhi, uimmlo;
      riscv_c_sw_decode_fields((uint16_t *)&encoding, &rs2, &rs1, &uimmhi, &uimmlo);
      unsigned int offset = inst == RISCV_C_SW
                              ? xtrace_riscv_c_word_offset(uimmhi, uimmlo)
                              : xtrace_riscv_c_doubleword_offset(uimmhi, uimmlo);
      if (inst == RISCV_C_FSD) {
        xtrace_appendf(buf, cap, pos, " %s, %u(%s)",
                       xtrace_riscv_freg(rs2 + s0), offset,
                       xtrace_riscv_reg(rs1 + s0));
      } else {
        xtrace_appendf(buf, cap, pos, " %s, %u(%s)",
                       xtrace_riscv_reg(rs2 + s0), offset,
                       xtrace_riscv_reg(rs1 + s0));
      }
      break;
    }
    case RISCV_C_FLWSP:
    case RISCV_C_FLDSP:
    case RISCV_C_LWSP:
    case RISCV_C_LDSP: {
      unsigned int rd, uimmhi, uimmlo;
      riscv_c_lwsp_decode_fields((uint16_t *)&encoding, &rd, &uimmhi, &uimmlo);
      unsigned int offset = (inst == RISCV_C_LWSP || inst == RISCV_C_FLWSP)
                              ? xtrace_riscv_c_spword_load_offset(uimmhi, uimmlo)
                              : xtrace_riscv_c_spdoubleword_load_offset(uimmhi, uimmlo);
      if (inst == RISCV_C_FLWSP || inst == RISCV_C_FLDSP) {
        xtrace_appendf(buf, cap, pos, " %s, %u(sp)",
                       xtrace_riscv_freg(rd), offset);
      } else {
        xtrace_appendf(buf, cap, pos, " %s, %u(sp)",
                       xtrace_riscv_reg(rd), offset);
      }
      break;
    }
    case RISCV_C_FSDSP:
    case RISCV_C_SWSP:
    case RISCV_C_SDSP: {
      unsigned int rs2, uimm;
      riscv_c_swsp_decode_fields((uint16_t *)&encoding, &rs2, &uimm);
      unsigned int offset = inst == RISCV_C_SWSP
                              ? xtrace_riscv_c_spword_store_offset(uimm)
                              : xtrace_riscv_c_spdoubleword_store_offset(uimm);
      if (inst == RISCV_C_FSDSP) {
        xtrace_appendf(buf, cap, pos, " %s, %u(sp)",
                       xtrace_riscv_freg(rs2), offset);
      } else {
        xtrace_appendf(buf, cap, pos, " %s, %u(sp)",
                       xtrace_riscv_reg(rs2), offset);
      }
      break;
    }
    case RISCV_C_ADDI:
    case RISCV_C_ADDIW: {
      unsigned int rd, immhi, immlo;
      riscv_c_addi_decode_fields((uint16_t *)&encoding, &rd, &immhi, &immlo);
      xtrace_appendf(buf, cap, pos, " %s, %s, %" PRId32,
                     xtrace_riscv_reg(rd), xtrace_riscv_reg(rd),
                     xtrace_riscv_c_imm(immhi, immlo));
      break;
    }
    case RISCV_C_LI: {
      unsigned int rd, immhi, immlo;
      riscv_c_addi_decode_fields((uint16_t *)&encoding, &rd, &immhi, &immlo);
      xtrace_appendf(buf, cap, pos, " %s, %" PRId32,
                     xtrace_riscv_reg(rd),
                     xtrace_riscv_c_imm(immhi, immlo));
      break;
    }
    case RISCV_C_ADDI16SP: {
      unsigned int immhi, immlo;
      riscv_c_addi16sp_decode_fields((uint16_t *)&encoding, &immhi, &immlo);
      xtrace_appendf(buf, cap, pos, " sp, sp, %" PRId32,
                     xtrace_riscv_c_addi16sp_imm(immhi, immlo));
      break;
    }
    case RISCV_C_LUI: {
      unsigned int rd, immhi, immlo;
      riscv_c_lui_decode_fields((uint16_t *)&encoding, &rd, &immhi, &immlo);
      int32_t imm = sign_extend32(18, ((immhi << 5) | immlo) << 12);
      xtrace_appendf(buf, cap, pos, " %s, %" PRId32,
                     xtrace_riscv_reg(rd), imm);
      break;
    }
    case RISCV_C_SLLI: {
      unsigned int rs1_rd, shhi, shlo;
      riscv_c_slli_decode_fields((uint16_t *)&encoding, &rs1_rd, &shhi, &shlo);
      xtrace_appendf(buf, cap, pos, " %s, %s, %u",
                     xtrace_riscv_reg(rs1_rd), xtrace_riscv_reg(rs1_rd),
                     (shhi << 5) | shlo);
      break;
    }
    case RISCV_C_SRLI:
    case RISCV_C_SRAI: {
      unsigned int rs1_rd, shhi, shlo;
      riscv_c_slli_decode_fields((uint16_t *)&encoding, &rs1_rd, &shhi, &shlo);
      xtrace_appendf(buf, cap, pos, " %s, %s, %u",
                     xtrace_riscv_reg(rs1_rd + s0),
                     xtrace_riscv_reg(rs1_rd + s0),
                     (shhi << 5) | shlo);
      break;
    }
    case RISCV_C_ANDI: {
      unsigned int rs1_rd, immhi, immlo;
      riscv_c_andi_decode_fields((uint16_t *)&encoding, &rs1_rd, &immhi, &immlo);
      xtrace_appendf(buf, cap, pos, " %s, %s, %" PRId32,
                     xtrace_riscv_reg(rs1_rd + s0),
                     xtrace_riscv_reg(rs1_rd + s0),
                     xtrace_riscv_c_imm(immhi, immlo));
      break;
    }
    case RISCV_C_SUB:
    case RISCV_C_XOR:
    case RISCV_C_OR:
    case RISCV_C_AND:
    case RISCV_C_SUBW:
    case RISCV_C_ADDW: {
      unsigned int rs1_rd, rs2;
      riscv_c_sub_decode_fields((uint16_t *)&encoding, &rs1_rd, &rs2);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s",
                     xtrace_riscv_reg(rs1_rd + s0),
                     xtrace_riscv_reg(rs1_rd + s0),
                     xtrace_riscv_reg(rs2 + s0));
      break;
    }
    case RISCV_C_ADD: {
      unsigned int rd, rs2;
      riscv_c_add_decode_fields((uint16_t *)&encoding, &rd, &rs2);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s",
                     xtrace_riscv_reg(rd),
                     xtrace_riscv_reg(rd), xtrace_riscv_reg(rs2));
      break;
    }
    case RISCV_C_MV: {
      unsigned int rd, rs2;
      riscv_c_add_decode_fields((uint16_t *)&encoding, &rd, &rs2);
      xtrace_appendf(buf, cap, pos, " %s, %s",
                     xtrace_riscv_reg(rd), xtrace_riscv_reg(rs2));
      break;
    }
    case RISCV_C_JR:
    case RISCV_C_JALR: {
      unsigned int rs1;
      riscv_c_jr_decode_fields((uint16_t *)&encoding, &rs1);
      xtrace_appendf(buf, cap, pos, " %s", xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_C_J:
    case RISCV_C_JAL: {
      unsigned int imm;
      riscv_c_j_decode_fields((uint16_t *)&encoding, &imm);
      int32_t offset = xtrace_riscv_c_j_offset(imm);
      xtrace_appendf(buf, cap, pos, " 0x%" PRIxPTR,
                     (uintptr_t)((intptr_t)pc + offset));
      break;
    }
    case RISCV_C_BEQZ:
    case RISCV_C_BNEZ: {
      unsigned int rs1, immhi, immlo;
      riscv_c_beqz_decode_fields((uint16_t *)&encoding, &rs1, &immhi, &immlo);
      int32_t offset = xtrace_riscv_c_branch_offset(immhi, immlo);
      xtrace_appendf(buf, cap, pos, " %s, 0x%" PRIxPTR,
                     xtrace_riscv_reg(rs1 + s0),
                     (uintptr_t)((intptr_t)pc + offset));
      break;
    }
    case RISCV_LB:
    case RISCV_LH:
    case RISCV_LW:
    case RISCV_LD:
    case RISCV_LBU:
    case RISCV_LHU:
    case RISCV_LWU: {
      unsigned int rd, rs1, imm;
      riscv_lw_decode_fields((uint16_t *)&encoding, &rd, &rs1, &imm);
      xtrace_appendf(buf, cap, pos, " %s, %" PRId32 "(%s)",
                     xtrace_riscv_reg(rd), sign_extend32(12, imm),
                     xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_FLW:
    case RISCV_FLD: {
      unsigned int rd, rs1, imm;
      riscv_flw_decode_fields((uint16_t *)&encoding, &rd, &rs1, &imm);
      xtrace_appendf(buf, cap, pos, " %s, %" PRId32 "(%s)",
                     xtrace_riscv_freg(rd), sign_extend32(12, imm),
                     xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_SB:
    case RISCV_SH:
    case RISCV_SW:
    case RISCV_SD: {
      unsigned int rs2, rs1, immhi, immlo;
      riscv_sw_decode_fields((uint16_t *)&encoding, &rs2, &rs1, &immhi, &immlo);
      int32_t offset = xtrace_riscv_store_offset(immhi, immlo);
      xtrace_appendf(buf, cap, pos, " %s, %" PRId32 "(%s)",
                     xtrace_riscv_reg(rs2), offset, xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_FSW:
    case RISCV_FSD: {
      unsigned int rs2, rs1, immhi, immlo;
      riscv_fsw_decode_fields((uint16_t *)&encoding, &rs2, &rs1, &immhi, &immlo);
      int32_t offset = xtrace_riscv_store_offset(immhi, immlo);
      xtrace_appendf(buf, cap, pos, " %s, %" PRId32 "(%s)",
                     xtrace_riscv_freg(rs2), offset, xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_FLH: {
      unsigned int offset, rs1, rd;
      riscv_flh_decode_fields((uint16_t *)&encoding, &offset, &rs1, &rd);
      xtrace_appendf(buf, cap, pos, " %s, %" PRId32 "(%s)",
                     xtrace_riscv_freg(rd), sign_extend32(12, offset),
                     xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_FSH: {
      unsigned int immhi, rs2, rs1, immlo;
      riscv_fsh_decode_fields((uint16_t *)&encoding, &immhi, &rs2, &rs1, &immlo);
      int32_t offset = xtrace_riscv_store_offset(immhi, immlo);
      xtrace_appendf(buf, cap, pos, " %s, %" PRId32 "(%s)",
                     xtrace_riscv_freg(rs2), offset, xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_ADDI:
    case RISCV_SLTI:
    case RISCV_SLTIU:
    case RISCV_XORI:
    case RISCV_ORI:
    case RISCV_ANDI:
    case RISCV_ADDIW: {
      unsigned int rd, rs1, imm;
      riscv_addi_decode_fields((uint16_t *)&encoding, &rd, &rs1, &imm);
      xtrace_appendf(buf, cap, pos, " %s, %s, %" PRId32,
                     xtrace_riscv_reg(rd), xtrace_riscv_reg(rs1),
                     sign_extend32(12, imm));
      break;
    }
    case RISCV_SLLI:
    case RISCV_SRLI:
    case RISCV_SRAI:
    case RISCV_SLLIW:
    case RISCV_SRLIW:
    case RISCV_SRAIW: {
      unsigned int rd, rs1, shamt;
      riscv_slli_decode_fields((uint16_t *)&encoding, &rd, &rs1, &shamt);
      xtrace_appendf(buf, cap, pos, " %s, %s, %u",
                     xtrace_riscv_reg(rd), xtrace_riscv_reg(rs1), shamt);
      break;
    }
    case RISCV_CSRRW:
    case RISCV_CSRRS:
    case RISCV_CSRRC: {
      unsigned int rd, csr, rs1;
      riscv_csrrw_decode_fields((uint16_t *)&encoding, &rd, &csr, &rs1);
      xtrace_appendf(buf, cap, pos, " %s, 0x%x, %s",
                     xtrace_riscv_reg(rd), csr, xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_CSRRWI:
    case RISCV_CSRRSI:
    case RISCV_CSRRCI: {
      unsigned int rd, csr, uimm;
      riscv_csrrwi_decode_fields((uint16_t *)&encoding, &rd, &csr, &uimm);
      xtrace_appendf(buf, cap, pos, " %s, 0x%x, %u",
                     xtrace_riscv_reg(rd), csr, uimm);
      break;
    }
    case RISCV_FENCE: {
      unsigned int fm, pred, succ;
      riscv_fence_decode_fields((uint16_t *)&encoding, &fm, &pred, &succ);
      if (fm == 8 && pred == 3 && succ == 3) {
        xtrace_appendf(buf, cap, pos, " tso");
      } else {
        xtrace_appendf(buf, cap, pos, " ");
        xtrace_append_riscv_fence_set(buf, cap, pos, pred);
        xtrace_appendf(buf, cap, pos, ", ");
        xtrace_append_riscv_fence_set(buf, cap, pos, succ);
        if (fm != 0) {
          xtrace_appendf(buf, cap, pos, ", fm=0x%x", fm);
        }
      }
      break;
    }
    case RISCV_ADD:
    case RISCV_SUB:
    case RISCV_SLL:
    case RISCV_SLT:
    case RISCV_SLTU:
    case RISCV_XOR:
    case RISCV_SRL:
    case RISCV_SRA:
    case RISCV_OR:
    case RISCV_AND:
    case RISCV_ADDW:
    case RISCV_SUBW:
    case RISCV_SLLW:
    case RISCV_SRLW:
    case RISCV_SRAW:
    case RISCV_MUL:
    case RISCV_MULH:
    case RISCV_MULHSU:
    case RISCV_MULHU:
    case RISCV_DIV:
    case RISCV_DIVU:
    case RISCV_REM:
    case RISCV_REMU:
    case RISCV_MULW:
    case RISCV_DIVW:
    case RISCV_DIVUW:
    case RISCV_REMW:
    case RISCV_REMUW: {
      unsigned int rd, rs1, rs2;
      riscv_add_decode_fields((uint16_t *)&encoding, &rd, &rs1, &rs2);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s",
                     xtrace_riscv_reg(rd), xtrace_riscv_reg(rs1),
                     xtrace_riscv_reg(rs2));
      break;
    }
    case RISCV_ADD_UW:
    case RISCV_SH1ADD:
    case RISCV_SH1ADD_UW:
    case RISCV_SH2ADD:
    case RISCV_SH2ADD_UW:
    case RISCV_SH3ADD:
    case RISCV_SH3ADD_UW:
    case RISCV_ANDN:
    case RISCV_ORN:
    case RISCV_XNOR:
    case RISCV_MAX:
    case RISCV_MAXU:
    case RISCV_MIN:
    case RISCV_MINU:
    case RISCV_ROL:
    case RISCV_ROLW:
    case RISCV_ROR:
    case RISCV_RORW:
    case RISCV_CLMUL:
    case RISCV_CLMULH:
    case RISCV_CLMULR:
    case RISCV_BCLR:
    case RISCV_BEXT:
    case RISCV_BINV:
    case RISCV_BSET:
    case RISCV_CZERO_EQZ:
    case RISCV_CZERO_NEZ: {
      unsigned int rs2, rs1, rd;
      riscv_add_uw_decode_fields((uint16_t *)&encoding, &rs2, &rs1, &rd);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s",
                     xtrace_riscv_reg(rd), xtrace_riscv_reg(rs1),
                     xtrace_riscv_reg(rs2));
      break;
    }
    case RISCV_SLLI_UW:
    case RISCV_RORI:
    case RISCV_RORIW:
    case RISCV_BCLRI:
    case RISCV_BEXTI:
    case RISCV_BINVI:
    case RISCV_BSETI: {
      unsigned int shamt, rs1, rd;
      riscv_slli_uw_decode_fields((uint16_t *)&encoding, &shamt, &rs1, &rd);
      xtrace_appendf(buf, cap, pos, " %s, %s, %u",
                     xtrace_riscv_reg(rd), xtrace_riscv_reg(rs1), shamt);
      break;
    }
    case RISCV_CLZ:
    case RISCV_CLZW:
    case RISCV_CTZ:
    case RISCV_CTZW:
    case RISCV_CPOP:
    case RISCV_CPOPW:
    case RISCV_SEXT_B:
    case RISCV_SEXT_H:
    case RISCV_ZEXT_H:
    case RISCV_ORC_B:
    case RISCV_REV8: {
      unsigned int rs1, rd;
      riscv_clz_decode_fields((uint16_t *)&encoding, &rs1, &rd);
      xtrace_appendf(buf, cap, pos, " %s, %s",
                     xtrace_riscv_reg(rd), xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_LUI:
    case RISCV_AUIPC: {
      unsigned int rd, imm;
      riscv_lui_decode_fields((uint16_t *)&encoding, &rd, &imm);
      xtrace_appendf(buf, cap, pos, " %s, 0x%x",
                     xtrace_riscv_reg(rd), imm);
      break;
    }
    case RISCV_LR_W:
    case RISCV_LR_D: {
      unsigned int aq, rl, rd, rs1;
      riscv_lr_w_decode_fields((uint16_t *)&encoding, &aq, &rl, &rd, &rs1);
      xtrace_append_riscv_aqrl(buf, cap, pos, aq, rl);
      xtrace_appendf(buf, cap, pos, " %s, (%s)",
                     xtrace_riscv_reg(rd), xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_SC_W:
    case RISCV_SC_D:
    case RISCV_AMOSWAP_W:
    case RISCV_AMOADD_W:
    case RISCV_AMOXOR_W:
    case RISCV_AMOAND_W:
    case RISCV_AMOOR_W:
    case RISCV_AMOMIN_W:
    case RISCV_AMOMAX_W:
    case RISCV_AMOMINU_W:
    case RISCV_AMOMAXU_W:
    case RISCV_AMOSWAP_D:
    case RISCV_AMOADD_D:
    case RISCV_AMOXOR_D:
    case RISCV_AMOAND_D:
    case RISCV_AMOOR_D:
    case RISCV_AMOMIN_D:
    case RISCV_AMOMAX_D:
    case RISCV_AMOMINU_D:
    case RISCV_AMOMAXU_D: {
      unsigned int aq, rl, rd, rs2, rs1;
      riscv_sc_w_decode_fields((uint16_t *)&encoding, &aq, &rl, &rd, &rs2, &rs1);
      xtrace_append_riscv_aqrl(buf, cap, pos, aq, rl);
      xtrace_appendf(buf, cap, pos, " %s, %s, (%s)",
                     xtrace_riscv_reg(rd), xtrace_riscv_reg(rs2),
                     xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_FMADD_S:
    case RISCV_FMSUB_S:
    case RISCV_FNMSUB_S:
    case RISCV_FNMADD_S:
    case RISCV_FMADD_D:
    case RISCV_FMSUB_D:
    case RISCV_FNMSUB_D:
    case RISCV_FNMADD_D: {
      unsigned int rd, rs1, rs2, rs3, rm;
      riscv_fmadd_s_decode_fields((uint16_t *)&encoding, &rd, &rs1, &rs2, &rs3, &rm);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s, %s, %s",
                     xtrace_riscv_freg(rd), xtrace_riscv_freg(rs1),
                     xtrace_riscv_freg(rs2), xtrace_riscv_freg(rs3),
                     xtrace_riscv_rm(rm));
      break;
    }
    case RISCV_FMADD_H:
    case RISCV_FMSUB_H:
    case RISCV_FNMSUB_H:
    case RISCV_FNMADD_H: {
      unsigned int rs3, rs2, rs1, rm, rd;
      riscv_fmadd_h_decode_fields((uint16_t *)&encoding, &rs3, &rs2, &rs1, &rm, &rd);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s, %s, %s",
                     xtrace_riscv_freg(rd), xtrace_riscv_freg(rs1),
                     xtrace_riscv_freg(rs2), xtrace_riscv_freg(rs3),
                     xtrace_riscv_rm(rm));
      break;
    }
    case RISCV_FADD_S:
    case RISCV_FSUB_S:
    case RISCV_FMUL_S:
    case RISCV_FDIV_S:
    case RISCV_FADD_D:
    case RISCV_FSUB_D:
    case RISCV_FMUL_D:
    case RISCV_FDIV_D: {
      unsigned int rd, rs1, rs2, rm;
      riscv_fadd_s_decode_fields((uint16_t *)&encoding, &rd, &rs1, &rs2, &rm);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s, %s",
                     xtrace_riscv_freg(rd), xtrace_riscv_freg(rs1),
                     xtrace_riscv_freg(rs2), xtrace_riscv_rm(rm));
      break;
    }
    case RISCV_FADD_H:
    case RISCV_FSUB_H:
    case RISCV_FMUL_H:
    case RISCV_FDIV_H: {
      unsigned int rs2, rs1, rm, rd;
      riscv_fadd_h_decode_fields((uint16_t *)&encoding, &rs2, &rs1, &rm, &rd);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s, %s",
                     xtrace_riscv_freg(rd), xtrace_riscv_freg(rs1),
                     xtrace_riscv_freg(rs2), xtrace_riscv_rm(rm));
      break;
    }
    case RISCV_FSQRT_S:
    case RISCV_FSQRT_D: {
      unsigned int rd, rs1, rm;
      riscv_fsqrt_s_decode_fields((uint16_t *)&encoding, &rd, &rs1, &rm);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s",
                     xtrace_riscv_freg(rd), xtrace_riscv_freg(rs1),
                     xtrace_riscv_rm(rm));
      break;
    }
    case RISCV_FSQRT_H: {
      unsigned int rs1, rm, rd;
      riscv_fsqrt_h_decode_fields((uint16_t *)&encoding, &rs1, &rm, &rd);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s",
                     xtrace_riscv_freg(rd), xtrace_riscv_freg(rs1),
                     xtrace_riscv_rm(rm));
      break;
    }
    case RISCV_FSGNJ_S:
    case RISCV_FSGNJN_S:
    case RISCV_FSGNJX_S:
    case RISCV_FMIN_S:
    case RISCV_FMAX_S:
    case RISCV_FSGNJ_D:
    case RISCV_FSGNJN_D:
    case RISCV_FSGNJX_D:
    case RISCV_FMIN_D:
    case RISCV_FMAX_D: {
      unsigned int rd, rs1, rs2;
      riscv_fsgnj_s_decode_fields((uint16_t *)&encoding, &rd, &rs1, &rs2);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s",
                     xtrace_riscv_freg(rd), xtrace_riscv_freg(rs1),
                     xtrace_riscv_freg(rs2));
      break;
    }
    case RISCV_FSGNJ_H:
    case RISCV_FSGNJN_H:
    case RISCV_FSGNJX_H:
    case RISCV_FMIN_H:
    case RISCV_FMAX_H: {
      unsigned int rs2, rs1, rd;
      riscv_fsgnj_h_decode_fields((uint16_t *)&encoding, &rs2, &rs1, &rd);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s",
                     xtrace_riscv_freg(rd), xtrace_riscv_freg(rs1),
                     xtrace_riscv_freg(rs2));
      break;
    }
    case RISCV_FEQ_S:
    case RISCV_FLT_S:
    case RISCV_FLE_S:
    case RISCV_FEQ_D:
    case RISCV_FLT_D:
    case RISCV_FLE_D: {
      unsigned int rd, rs1, rs2;
      riscv_feq_s_decode_fields((uint16_t *)&encoding, &rd, &rs1, &rs2);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s",
                     xtrace_riscv_reg(rd), xtrace_riscv_freg(rs1),
                     xtrace_riscv_freg(rs2));
      break;
    }
    case RISCV_FEQ_H:
    case RISCV_FLT_H:
    case RISCV_FLE_H: {
      unsigned int rs2, rs1, rd;
      riscv_feq_h_decode_fields((uint16_t *)&encoding, &rs2, &rs1, &rd);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s",
                     xtrace_riscv_reg(rd), xtrace_riscv_freg(rs1),
                     xtrace_riscv_freg(rs2));
      break;
    }
    case RISCV_FCLASS_S:
    case RISCV_FCLASS_D:
    case RISCV_FMV_X_W:
    case RISCV_FMV_X_D: {
      unsigned int rd, rs1;
      riscv_fmv_x_w_decode_fields((uint16_t *)&encoding, &rd, &rs1);
      xtrace_appendf(buf, cap, pos, " %s, %s",
                     xtrace_riscv_reg(rd), xtrace_riscv_freg(rs1));
      break;
    }
    case RISCV_FCLASS_H:
    case RISCV_FMV_X_H: {
      unsigned int rs1, rd;
      riscv_fmv_x_h_decode_fields((uint16_t *)&encoding, &rs1, &rd);
      xtrace_appendf(buf, cap, pos, " %s, %s",
                     xtrace_riscv_reg(rd), xtrace_riscv_freg(rs1));
      break;
    }
    case RISCV_FMV_W_X:
    case RISCV_FMV_D_X: {
      unsigned int rd, rs1;
      riscv_fmv_w_x_decode_fields((uint16_t *)&encoding, &rd, &rs1);
      xtrace_appendf(buf, cap, pos, " %s, %s",
                     xtrace_riscv_freg(rd), xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_FMV_H_X: {
      unsigned int rs1, rd;
      riscv_fmv_h_x_decode_fields((uint16_t *)&encoding, &rs1, &rd);
      xtrace_appendf(buf, cap, pos, " %s, %s",
                     xtrace_riscv_freg(rd), xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_FCVT_W_S:
    case RISCV_FCVT_WU_S:
    case RISCV_FCVT_L_S:
    case RISCV_FCVT_LU_S:
    case RISCV_FCVT_W_D:
    case RISCV_FCVT_WU_D:
    case RISCV_FCVT_L_D:
    case RISCV_FCVT_LU_D: {
      unsigned int rd, rs1, rm;
      riscv_fcvt_w_s_decode_fields((uint16_t *)&encoding, &rd, &rs1, &rm);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s",
                     xtrace_riscv_reg(rd), xtrace_riscv_freg(rs1),
                     xtrace_riscv_rm(rm));
      break;
    }
    case RISCV_FCVT_W_H:
    case RISCV_FCVT_WU_H:
    case RISCV_FCVT_L_H:
    case RISCV_FCVT_LU_H: {
      unsigned int rs1, rm, rd;
      riscv_fcvt_w_h_decode_fields((uint16_t *)&encoding, &rs1, &rm, &rd);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s",
                     xtrace_riscv_reg(rd), xtrace_riscv_freg(rs1),
                     xtrace_riscv_rm(rm));
      break;
    }
    case RISCV_FCVT_S_W:
    case RISCV_FCVT_S_WU:
    case RISCV_FCVT_S_L:
    case RISCV_FCVT_S_LU:
    case RISCV_FCVT_D_W:
    case RISCV_FCVT_D_WU:
    case RISCV_FCVT_D_L:
    case RISCV_FCVT_D_LU: {
      unsigned int rd, rs1, rm;
      riscv_fcvt_s_w_decode_fields((uint16_t *)&encoding, &rd, &rs1, &rm);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s",
                     xtrace_riscv_freg(rd), xtrace_riscv_reg(rs1),
                     xtrace_riscv_rm(rm));
      break;
    }
    case RISCV_FCVT_H_W:
    case RISCV_FCVT_H_WU:
    case RISCV_FCVT_H_L:
    case RISCV_FCVT_H_LU: {
      unsigned int rs1, rm, rd;
      riscv_fcvt_h_w_decode_fields((uint16_t *)&encoding, &rs1, &rm, &rd);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s",
                     xtrace_riscv_freg(rd), xtrace_riscv_reg(rs1),
                     xtrace_riscv_rm(rm));
      break;
    }
    case RISCV_FCVT_S_D:
    case RISCV_FCVT_D_S: {
      unsigned int rd, rs1, rm;
      riscv_fcvt_s_d_decode_fields((uint16_t *)&encoding, &rd, &rs1, &rm);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s",
                     xtrace_riscv_freg(rd), xtrace_riscv_freg(rs1),
                     xtrace_riscv_rm(rm));
      break;
    }
    case RISCV_FCVT_S_H:
    case RISCV_FCVT_H_S:
    case RISCV_FCVT_D_H:
    case RISCV_FCVT_H_D: {
      unsigned int rs1, rm, rd;
      riscv_fcvt_s_h_decode_fields((uint16_t *)&encoding, &rs1, &rm, &rd);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s",
                     xtrace_riscv_freg(rd), xtrace_riscv_freg(rs1),
                     xtrace_riscv_rm(rm));
      break;
    }
    case RISCV_CBO_CLEAN:
    case RISCV_CBO_FLUSH:
    case RISCV_CBO_INVAL:
    case RISCV_CBO_ZERO: {
      unsigned int rs1;
      riscv_cbo_clean_decode_fields((uint16_t *)&encoding, &rs1);
      xtrace_appendf(buf, cap, pos, " (%s)", xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_PREFETCH_I:
    case RISCV_PREFETCH_R:
    case RISCV_PREFETCH_W: {
      unsigned int offset, rs1;
      riscv_prefetch_i_decode_fields((uint16_t *)&encoding, &offset, &rs1);
      xtrace_appendf(buf, cap, pos, " %u(%s)",
                     offset, xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_V_OP: {
      unsigned int funct, rs1_vs1, funct3, rd_vd;
      riscv_v_op_decode_fields((uint16_t *)&encoding, &funct, &rs1_vs1, &funct3, &rd_vd);
      xtrace_appendf(buf, cap, pos, " v%u, rs1/vs1=%u, funct=0x%x, funct3=0x%x",
                     rd_vd, rs1_vs1, funct, funct3);
      break;
    }
    case RISCV_V_LOAD_B:
    case RISCV_V_LOAD_H:
    case RISCV_V_LOAD_W:
    case RISCV_V_LOAD_D: {
      unsigned int lumop, rs1, vd;
      riscv_v_load_b_decode_fields((uint16_t *)&encoding, &lumop, &rs1, &vd);
      xtrace_appendf(buf, cap, pos, " v%u, (%s), lumop=0x%x",
                     vd, xtrace_riscv_reg(rs1), lumop);
      break;
    }
    case RISCV_V_STORE_B:
    case RISCV_V_STORE_H:
    case RISCV_V_STORE_W:
    case RISCV_V_STORE_D: {
      unsigned int sumop, rs1, vs3;
      riscv_v_store_b_decode_fields((uint16_t *)&encoding, &sumop, &rs1, &vs3);
      xtrace_appendf(buf, cap, pos, " v%u, (%s), sumop=0x%x",
                     vs3, xtrace_riscv_reg(rs1), sumop);
      break;
    }
    case RISCV_V_AMO_B:
    case RISCV_V_AMO_H:
    case RISCV_V_AMO_W:
    case RISCV_V_AMO_D: {
      unsigned int amoop, rs1, vd;
      riscv_v_amo_b_decode_fields((uint16_t *)&encoding, &amoop, &rs1, &vd);
      xtrace_appendf(buf, cap, pos, " v%u, (%s), amoop=0x%x",
                     vd, xtrace_riscv_reg(rs1), amoop);
      break;
    }
    case RISCV_JAL: {
      unsigned int rd, imm;
      riscv_jal_decode_fields((uint16_t *)&encoding, &rd, &imm);
      int32_t offset = xtrace_riscv_jal_offset(imm);
      xtrace_appendf(buf, cap, pos, " %s, 0x%" PRIxPTR,
                     xtrace_riscv_reg(rd),
                     (uintptr_t)((intptr_t)pc + offset));
      break;
    }
    case RISCV_JALR: {
      unsigned int rd, rs1, imm;
      riscv_jalr_decode_fields((uint16_t *)&encoding, &rd, &rs1, &imm);
      xtrace_appendf(buf, cap, pos, " %s, %" PRId32 "(%s)",
                     xtrace_riscv_reg(rd), sign_extend32(12, imm),
                     xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_BEQ:
    case RISCV_BNE:
    case RISCV_BLT:
    case RISCV_BGE:
    case RISCV_BLTU:
    case RISCV_BGEU: {
      unsigned int rs1, rs2, immhi, immlo;
      riscv_blt_decode_fields((uint16_t *)&encoding, &rs1, &rs2, &immhi, &immlo);
      int32_t offset = xtrace_riscv_branch_offset(immhi, immlo);
      xtrace_appendf(buf, cap, pos, " %s, %s, 0x%" PRIxPTR,
                     xtrace_riscv_reg(rs1), xtrace_riscv_reg(rs2),
                     (uintptr_t)((intptr_t)pc + offset));
      break;
    }
    case RISCV_BRANCH: {
      unsigned int funct3, rs1, rs2, immhi, immlo;
      riscv_branch_decode_fields((uint16_t *)&encoding, &funct3, &rs1, &rs2,
                                 &immhi, &immlo);
      int32_t offset = xtrace_riscv_branch_offset(immhi, immlo);
      xtrace_appendf(buf, cap, pos, " cond=%u, %s, %s, 0x%" PRIxPTR,
                     funct3, xtrace_riscv_reg(rs1), xtrace_riscv_reg(rs2),
                     (uintptr_t)((intptr_t)pc + offset));
      break;
    }
    default:
      break;
  }
}
#endif

static void xtrace_format_inst_text(char *buf, size_t cap, size_t *pos,
                                    uintptr_t pc, uintptr_t encoding,
                                    int inst_type, int inst) {
  if (inst < 0) {
    xtrace_appendf(buf, cap, pos, "unknown");
    return;
  }

#ifdef __aarch64__
  if (inst_type == A64_INST) {
    xtrace_appendf(buf, cap, pos, "%s", xtrace_a64_mnemonic(inst, encoding));
    xtrace_append_a64_operands(buf, cap, pos, pc, encoding, inst);
    return;
  }
#endif

  xtrace_appendf(buf, cap, pos, "%s", xtrace_inst_name(inst_type, inst));

#ifdef __riscv
  if (inst_type == RISCV_INST) {
    xtrace_append_riscv_operands(buf, cap, pos, pc, encoding, inst);
  }
#endif
}

#ifndef XTRACE_DECODER
static uint8_t xtrace_arch_id(void) {
#if defined(__aarch64__)
  return XTRACE_ARCH_AARCH64;
#elif defined(__arm__)
  return XTRACE_ARCH_ARM;
#elif defined(__riscv) && __riscv_xlen == 64
  return XTRACE_ARCH_RISCV64;
#else
  return XTRACE_ARCH_UNKNOWN;
#endif
}

static void xtrace_write_file_header(void) {
  struct xtrace_file_header header = {0};
  uint16_t endian = 1;

  memcpy(header.magic, XTRACE_FILE_MAGIC, sizeof(header.magic));
  header.version = XTRACE_FILE_VERSION;
  header.header_size = sizeof(header);
  header.event_size = sizeof(struct xtrace_event);
  header.byte_order = *(uint8_t *)&endian == 1 ? 1 : 2;
  header.pointer_size = sizeof(uintptr_t);
  header.arch = xtrace_arch_id();
  header.flags = (xtrace_timestamp_mode != XTRACE_TIMESTAMP_NONE
                      ? XTRACE_FILE_FLAG_CLOCK_TIMESTAMPS
                      : 0) |
                 (xtrace_has_base_override
                      ? XTRACE_FILE_FLAG_BASE_OVERRIDE
                      : 0);
  header.ring_level = xtrace_ring_level;
  header.compression_level = (uint32_t)xtrace_compression_level;
  header.base_override = xtrace_has_base_override ? xtrace_base_override : 0;
  header.timestamp_frequency_hz =
      xtrace_timestamp_mode == XTRACE_TIMESTAMP_CLOCK ? xtrace_cpu_hz : 0;

  if (fwrite(&header, sizeof(header), 1, xtrace_file) != 1) {
    fprintf(stderr, "xtrace: failed to write trace header: %s\n",
            strerror(errno));
    xtrace_output_failed = true;
  } else {
    xtrace_total_stored_bytes = sizeof(header);
  }
}

static void xtrace_flush_thread(struct xtrace_thread *thread) {
  if (!xtrace_binary || thread->event_count == 0) {
    return;
  }

  size_t raw_size = thread->event_count * sizeof(*thread->events);
  const void *stored = thread->events;
  size_t stored_size = raw_size;
  uint32_t flags = 0;

  size_t compressed_size = ZSTD_compressCCtx(
      thread->compression_ctx, thread->compressed, thread->compressed_capacity,
      thread->events, raw_size, xtrace_compression_level);
  if (!ZSTD_isError(compressed_size) && compressed_size < raw_size) {
    stored = thread->compressed;
    stored_size = compressed_size;
    flags = XTRACE_BLOCK_FLAG_ZSTD;
  }

  struct xtrace_block_header block = {
      .magic = XTRACE_BLOCK_MAGIC,
      .header_size = sizeof(block),
      .thread_id = thread->id,
      .event_count = thread->event_count,
      .raw_size = (uint32_t)raw_size,
      .stored_size = (uint32_t)stored_size,
      .flags = flags,
  };

  pthread_mutex_lock(&xtrace_output_lock);
  if (!xtrace_output_failed &&
      (fwrite(&block, sizeof(block), 1, xtrace_file) != 1 ||
       fwrite(stored, stored_size, 1, xtrace_file) != 1)) {
    fprintf(stderr, "xtrace: trace write failed: %s; disabling output\n",
            strerror(errno));
    xtrace_output_failed = true;
  } else if (!xtrace_output_failed) {
    xtrace_total_events += thread->event_count;
    xtrace_total_raw_bytes += raw_size;
    xtrace_total_stored_bytes += sizeof(block) + stored_size;
  }
  pthread_mutex_unlock(&xtrace_output_lock);
  thread->event_count = 0;
}

static struct xtrace_event *xtrace_next_event(struct xtrace_thread *thread) {
  if (thread->event_count == XTRACE_EVENTS_PER_BLOCK) {
    xtrace_flush_thread(thread);
  }
  return &thread->events[thread->event_count++];
}

static void xtrace_capture_value(struct xtrace_event *event, uintptr_t addr,
                                 uintptr_t size) {
  size_t copied = size;
  if (copied > XTRACE_MAX_BYTE_VALUE) {
    copied = XTRACE_MAX_BYTE_VALUE;
    event->flags |= XTRACE_EVENT_FLAG_VALUE_TRUNCATED;
  }
  if (copied != 0) {
    memcpy(&event->data_lo, (void *)addr, copied);
  }
}

void xtrace_record_inst(struct xtrace_thread *thread, uintptr_t pc,
                        uintptr_t encoding, uintptr_t info) {
  uintptr_t inst_len = info & 0xf;
  uintptr_t meta = info >> 4;

  if (xtrace_binary) {
    /* Keep an instruction and its possible load+store records in one block. */
    if (thread->event_count > XTRACE_EVENTS_PER_BLOCK - 3) {
      xtrace_flush_thread(thread);
    }
    bool timestamp_sample =
        xtrace_timestamp_mode != XTRACE_TIMESTAMP_NONE &&
        thread->instruction_count % XTRACE_TIMESTAMP_SAMPLE_INTERVAL == 0;
    struct xtrace_event *event = xtrace_next_event(thread);
    *event = (struct xtrace_event){
        .address = pc,
        .data_lo = encoding,
        .data_hi = timestamp_sample ? xtrace_timestamp() : 0,
        .meta = (uint32_t)meta,
        .size = (uint16_t)inst_len,
        .type = XTRACE_EVENT_INST,
        .flags = timestamp_sample
                     ? XTRACE_EVENT_FLAG_TIMESTAMP_SAMPLE
                     : 0,
    };
    thread->instruction_count++;
    return;
  }

  char line[256];
  size_t pos = 0;
  int inst_type = xtrace_meta_inst_type(meta);
  int inst = xtrace_meta_inst(meta);

  bool discontinuity = thread->has_next_pc && pc != thread->next_pc;
  xtrace_print_ring_line(pc, discontinuity);
  uint64_t stamp = xtrace_timestamp_mode == XTRACE_TIMESTAMP_NONE
                       ? 0
                       : xtrace_timestamp();
  if (xtrace_timestamp_mode == XTRACE_TIMESTAMP_CLOCK && xtrace_cpu_hz != 0) {
    stamp = xtrace_scale_timestamp(stamp, xtrace_cpu_hz);
  }
  xtrace_appendf(line, sizeof(line), &pos, "%" PRIxPTR " @%" PRIx64 ": ",
                 pc, stamp);
  xtrace_format_bytes(line, sizeof(line), &pos, encoding, inst_len);
  xtrace_appendf(line, sizeof(line), &pos, "  ");
  xtrace_format_inst_text(line, sizeof(line), &pos, pc, encoding,
                          inst_type, inst);
  xtrace_appendf(line, sizeof(line), &pos, "\n");
  thread->next_pc = pc + inst_len;
  thread->has_next_pc = true;
  fputs(line, xtrace_file);
}

void xtrace_record_access_pre(struct xtrace_thread *thread, uintptr_t pc,
                              uintptr_t addr, uintptr_t info) {
  (void)pc;
  uintptr_t size = info >> XTRACE_INFO_SIZE_SHIFT;

  if (info & XTRACE_INFO_LOAD) {
    if (xtrace_binary) {
      struct xtrace_event *event = xtrace_next_event(thread);
      *event = (struct xtrace_event){
          .address = addr,
          .meta = size > UINT32_MAX ? UINT32_MAX : (uint32_t)size,
          .size = size > UINT16_MAX ? UINT16_MAX : (uint16_t)size,
          .type = XTRACE_EVENT_LOAD,
      };
      xtrace_capture_value(event, addr, size);
    } else {
      fprintf(xtrace_file, " - LD %" PRIuPTR " M[%" PRIxPTR "] -> ",
              size * 8, addr);
      xtrace_print_mem_value(addr, size);
      fprintf(xtrace_file, "\n");
    }
  }

  if (info & XTRACE_INFO_STORE) {
    thread->store_addr = addr;
    thread->store_info = info;
    thread->store_pending = true;
  }
}

void xtrace_record_store_post(struct xtrace_thread *thread) {
  if (!thread->store_pending) {
    return;
  }

  uintptr_t size = thread->store_info >> XTRACE_INFO_SIZE_SHIFT;
  if (xtrace_binary) {
    struct xtrace_event *event = xtrace_next_event(thread);
    *event = (struct xtrace_event){
        .address = thread->store_addr,
        .meta = size > UINT32_MAX ? UINT32_MAX : (uint32_t)size,
        .size = size > UINT16_MAX ? UINT16_MAX : (uint16_t)size,
        .type = XTRACE_EVENT_STORE,
    };
    xtrace_capture_value(event, thread->store_addr, size);
  } else {
    fprintf(xtrace_file, " - ST %" PRIuPTR " M[%" PRIxPTR "] <- ",
            size * 8, thread->store_addr);
    xtrace_print_mem_value(thread->store_addr, size);
    fprintf(xtrace_file, "\n");
  }

  thread->store_pending = false;
}

int xtrace_pre_inst_handler(mambo_context *ctx) {
  struct xtrace_thread *thread = mambo_get_thread_plugin_data(ctx);
  if (!thread->instrument_block) {
    return 0;
  }

  bool is_load = mambo_is_load(ctx);
  bool is_store = mambo_is_store(ctx);
  bool is_mem = is_load || is_store;

  bool is_rvv = is_mem && mambo_is_rvv_mem(ctx);
  int size = is_mem ? mambo_get_ld_st_size(ctx) : 0;
  if (is_mem && !is_rvv && size <= 0) {
    return 0;
  }

  mambo_cond cond = mambo_get_cond(ctx);
  mambo_branch skip_br;
  int ret;
  if (cond != AL) {
    ret = mambo_reserve_branch(ctx, &skip_br);
    assert(ret == 0);
  }

#ifdef __riscv
  emit_push(ctx, (1 << a0) | (1 << a1) | (1 << a2) | (1 << a3) | (1 << lr));
  emit_set_reg_ptr(ctx, a0, mambo_get_thread_plugin_data(ctx));
  emit_set_reg_ptr(ctx, a1, (void *)xtrace_source_addr(ctx));
  emit_set_reg(ctx, a2, xtrace_inst_encoding(ctx));
  emit_set_reg(ctx, a3, xtrace_inst_info(ctx));
  ret = emit_safe_fcall(ctx, xtrace_record_inst, 4);
  assert(ret == 0);
  emit_pop(ctx, (1 << a0) | (1 << a1) | (1 << a2) | (1 << a3) | (1 << lr));
#else
  emit_push(ctx, (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << lr));
  emit_set_reg_ptr(ctx, 0, mambo_get_thread_plugin_data(ctx));
  emit_set_reg_ptr(ctx, 1, (void *)xtrace_source_addr(ctx));
  emit_set_reg(ctx, 2, xtrace_inst_encoding(ctx));
  emit_set_reg(ctx, 3, xtrace_inst_info(ctx));
  ret = emit_safe_fcall(ctx, xtrace_record_inst, 4);
  assert(ret == 0);
  emit_pop(ctx, (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << lr));
#endif

  if (!is_mem) {
    if (cond != AL) {
      ret = emit_local_branch_cond(ctx, &skip_br, invert_cond(cond));
      assert(ret == 0);
    }
    return 0;
  }

#ifdef __riscv
  emit_push(ctx, (1 << a0) | (1 << a1) | (1 << a2) | (1 << a3) | (1 << lr));
  ret = mambo_calc_ld_st_addr(ctx, a2);
  assert(ret == 0);

  if (is_rvv) {
    ret = mambo_calc_rvv_ld_st_size(ctx, a3, a1);
    assert(ret == 0);
    emit_riscv_slli(ctx, a3, a3, XTRACE_INFO_SIZE_SHIFT);
    if (is_load) {
      emit_riscv_ori(ctx, a3, a3, XTRACE_INFO_LOAD);
    }
    if (is_store) {
      emit_riscv_ori(ctx, a3, a3, XTRACE_INFO_STORE);
    }
  } else {
    emit_set_reg(ctx, a3,
                 ((uintptr_t)size << XTRACE_INFO_SIZE_SHIFT) |
                 (is_load ? XTRACE_INFO_LOAD : 0) |
                 (is_store ? XTRACE_INFO_STORE : 0));
  }
  emit_set_reg_ptr(ctx, a0, mambo_get_thread_plugin_data(ctx));
  emit_set_reg_ptr(ctx, a1, (void *)xtrace_source_addr(ctx));
#else
  emit_push(ctx, (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << lr));
  ret = mambo_calc_ld_st_addr(ctx, 2);
  assert(ret == 0);

  emit_set_reg(ctx, 3,
               ((uintptr_t)size << XTRACE_INFO_SIZE_SHIFT) |
               (is_load ? XTRACE_INFO_LOAD : 0) |
               (is_store ? XTRACE_INFO_STORE : 0));
  emit_set_reg_ptr(ctx, 0, mambo_get_thread_plugin_data(ctx));
  emit_set_reg_ptr(ctx, 1, (void *)xtrace_source_addr(ctx));
#endif

  ret = emit_safe_fcall(ctx, xtrace_record_access_pre, 4);
  assert(ret == 0);

#ifdef __riscv
  emit_pop(ctx, (1 << a0) | (1 << a1) | (1 << a2) | (1 << a3) | (1 << lr));
#else
  emit_pop(ctx, (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << lr));
#endif

  if (cond != AL) {
    ret = emit_local_branch_cond(ctx, &skip_br, invert_cond(cond));
    assert(ret == 0);
  }

  return 0;
}

int xtrace_post_inst_handler(mambo_context *ctx) {
  struct xtrace_thread *thread = mambo_get_thread_plugin_data(ctx);
  if (!thread->instrument_block) {
    return 0;
  }

  if (!mambo_is_store(ctx)) {
    return 0;
  }

  mambo_cond cond = mambo_get_cond(ctx);
  mambo_branch skip_br;
  int ret;
  if (cond != AL) {
    ret = mambo_reserve_branch(ctx, &skip_br);
    assert(ret == 0);
  }

#ifdef __riscv
  emit_push(ctx, (1 << a0) | (1 << lr));
  emit_set_reg_ptr(ctx, a0, mambo_get_thread_plugin_data(ctx));
#else
  emit_push(ctx, (1 << 0) | (1 << lr));
  emit_set_reg_ptr(ctx, 0, mambo_get_thread_plugin_data(ctx));
#endif

  ret = emit_safe_fcall(ctx, xtrace_record_store_post, 1);
  assert(ret == 0);

#ifdef __riscv
  emit_pop(ctx, (1 << a0) | (1 << lr));
#else
  emit_pop(ctx, (1 << 0) | (1 << lr));
#endif

  if (cond != AL) {
    ret = emit_local_branch_cond(ctx, &skip_br, invert_cond(cond));
    assert(ret == 0);
  }

  return 0;
}

int xtrace_pre_basic_block_handler(mambo_context *ctx) {
  struct xtrace_thread *thread = mambo_get_thread_plugin_data(ctx);
  assert(thread != NULL);
  thread->instrument_block =
      xtrace_should_instrument(thread, xtrace_source_addr(ctx));
  return 0;
}

int xtrace_pre_thread_handler(mambo_context *ctx) {
  struct xtrace_thread *thread = mambo_alloc(ctx, sizeof(*thread));
  assert(thread != NULL);

  memset(thread, 0, sizeof(*thread));
  thread->id = __atomic_fetch_add(&xtrace_next_thread_id, 1,
                                  __ATOMIC_RELAXED);
  thread->store_pending = false;

  if (xtrace_binary) {
    size_t raw_capacity = XTRACE_EVENTS_PER_BLOCK *
                          sizeof(struct xtrace_event);
    thread->events = malloc(raw_capacity);
    thread->compressed_capacity = ZSTD_compressBound(raw_capacity);
    thread->compressed = malloc(thread->compressed_capacity);
    thread->compression_ctx = ZSTD_createCCtx();
    if (thread->events == NULL || thread->compressed == NULL ||
        thread->compression_ctx == NULL) {
      fprintf(stderr, "xtrace: failed to allocate a thread trace buffer\n");
      abort();
    }
  }

  int ret = mambo_set_thread_plugin_data(ctx, thread);
  assert(ret == MAMBO_SUCCESS);

  return 0;
}

int xtrace_post_thread_handler(mambo_context *ctx) {
  struct xtrace_thread *thread = mambo_get_thread_plugin_data(ctx);
  xtrace_flush_thread(thread);
  ZSTD_freeCCtx(thread->compression_ctx);
  free(thread->events);
  free(thread->compressed);
  mambo_free(ctx, thread);

  return 0;
}

int xtrace_exit_handler(mambo_context *ctx) {
  (void)ctx;
  if (xtrace_binary) {
    struct xtrace_block_header eof = {
        .magic = XTRACE_EOF_MAGIC,
        .header_size = sizeof(eof),
    };
    if (!xtrace_output_failed) {
      if (fwrite(&eof, sizeof(eof), 1, xtrace_file) == 1) {
        xtrace_total_stored_bytes += sizeof(eof);
      } else {
        fprintf(stderr, "xtrace: failed to write EOF block: %s\n",
                strerror(errno));
        xtrace_output_failed = true;
      }
    }
  } else {
    fprintf(xtrace_file, "#eof\n");
  }
  if (fflush(xtrace_file) != 0) {
    fprintf(stderr, "xtrace: failed to flush trace output: %s\n",
            strerror(errno));
    xtrace_output_failed = true;
  }

  if (xtrace_binary && xtrace_total_raw_bytes != 0) {
    fprintf(stderr,
            "xtrace: %" PRIu64 " events, %" PRIu64
            " raw bytes, %" PRIu64 " stored bytes (%.2fx)%s\n",
            xtrace_total_events, xtrace_total_raw_bytes,
            xtrace_total_stored_bytes,
            (double)xtrace_total_raw_bytes / xtrace_total_stored_bytes,
            xtrace_output_failed ? ", output incomplete" : "");
  }

  if (xtrace_selective_capture) {
    for (size_t i = 0; i < xtrace_function_filter_count; i++) {
      if (!__atomic_load_n(&xtrace_function_filters[i].matched,
                           __ATOMIC_RELAXED)) {
        fprintf(stderr, "xtrace: function '%s' was not matched in translated "
                        "executable code (missing symbol or not executed)\n",
                xtrace_function_filters[i].name);
      }
      free(xtrace_function_filters[i].name);
    }
    free(xtrace_function_filters);
    free(xtrace_function_ranges);
  }

  if (xtrace_close_file) {
    fclose(xtrace_file);
  }
  return 0;
}

__attribute__((constructor)) void xtrace_init_plugin(void) {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  xtrace_parse_config();
  xtrace_start_stamp = xtrace_read_stamp();
  xtrace_open_file();
  if (xtrace_binary) {
    xtrace_write_file_header();
  }

  mambo_register_pre_thread_cb(ctx, &xtrace_pre_thread_handler);
  mambo_register_post_thread_cb(ctx, &xtrace_post_thread_handler);
  if (xtrace_selective_capture) {
    mambo_register_vm_op_cb(ctx, &xtrace_vm_op_handler);
  }
  mambo_register_pre_basic_block_cb(ctx, &xtrace_pre_basic_block_handler);
  mambo_register_pre_inst_cb(ctx, &xtrace_pre_inst_handler);
  mambo_register_post_inst_cb(ctx, &xtrace_post_inst_handler);
  mambo_register_exit_cb(ctx, &xtrace_exit_handler);
}

#endif /* !XTRACE_DECODER */

#ifdef XTRACE_DECODER
static uint8_t xtrace_decoder_arch(void) {
#if defined(__aarch64__)
  return XTRACE_ARCH_AARCH64;
#elif defined(__arm__)
  return XTRACE_ARCH_ARM;
#elif defined(__riscv) && __riscv_xlen == 64
  return XTRACE_ARCH_RISCV64;
#else
  return XTRACE_ARCH_UNKNOWN;
#endif
}

static int xtrace_decoder_value(FILE *out, const struct xtrace_event *event) {
  uintptr_t size = event->meta;
  if (size == 0) {
    return fprintf(out, "?") < 0 ? -1 : 0;
  }

  if (size <= sizeof(uint64_t)) {
    uint64_t value = event->data_lo;
    if (size < sizeof(value)) {
      value &= (1ull << (size * 8)) - 1;
    }
    return fprintf(out, "%" PRIx64, value) < 0 ? -1 : 0;
  }

  const unsigned char *bytes = (const unsigned char *)&event->data_lo;
  size_t count = size > XTRACE_MAX_BYTE_VALUE
                     ? XTRACE_MAX_BYTE_VALUE
                     : (size_t)size;
  for (size_t i = 0; i < count; i++) {
    if (fprintf(out, "%02x", bytes[i]) < 0) {
      return -1;
    }
  }
  if ((event->flags & XTRACE_EVENT_FLAG_VALUE_TRUNCATED) != 0) {
    return fprintf(out, "...") < 0 ? -1 : 0;
  }
  return 0;
}

struct xtrace_decode_thread {
  uint64_t sampled_stamp;
  uint64_t next_pc;
  bool has_sampled_stamp;
  bool has_next_pc;
};

static int xtrace_decode_event(FILE *out,
                               const struct xtrace_file_header *header,
                               const struct xtrace_event *event,
                               struct xtrace_decode_thread *thread,
                               bool *ring_written) {
  if (event->type == XTRACE_EVENT_INST) {
    char line[256];
    size_t pos = 0;
    uintptr_t meta = event->meta;
    uint64_t stamp;

    bool first_ring = !*ring_written;
    bool discontinuity = thread->has_next_pc &&
                         event->address != thread->next_pc;
    if (first_ring || discontinuity) {
      uint64_t target = first_ring &&
                                (header->flags &
                                 XTRACE_FILE_FLAG_BASE_OVERRIDE) != 0
                            ? header->base_override
                            : event->address;
      if (fprintf(out, "ring %d, pc -> %" PRIx64 "\n",
                  header->ring_level, target) < 0) {
        return -1;
      }
      *ring_written = true;
    }

    if ((header->flags & XTRACE_FILE_FLAG_CYCLE_TIMESTAMPS) != 0) {
      stamp = event->data_hi;
    } else if ((header->flags & XTRACE_FILE_FLAG_CLOCK_TIMESTAMPS) != 0) {
      if ((event->flags & XTRACE_EVENT_FLAG_TIMESTAMP_SAMPLE) != 0) {
        thread->sampled_stamp = event->data_hi;
        thread->has_sampled_stamp = true;
      }
      if (!thread->has_sampled_stamp) {
        fprintf(stderr,
                "xtrace-decode: instruction stream starts without a "
                "timestamp sample\n");
        return -1;
      }
      stamp = thread->sampled_stamp;
      if (header->timestamp_frequency_hz != 0) {
        stamp = xtrace_scale_timestamp(stamp,
                                       header->timestamp_frequency_hz);
      }
    } else {
      stamp = 0;
    }

    xtrace_appendf(line, sizeof(line), &pos, "%" PRIx64 " @%" PRIx64 ": ",
                   event->address, stamp);
    xtrace_format_bytes(line, sizeof(line), &pos, event->data_lo,
                        event->size);
    xtrace_appendf(line, sizeof(line), &pos, "  ");
    xtrace_format_inst_text(line, sizeof(line), &pos, event->address,
                            event->data_lo, xtrace_meta_inst_type(meta),
                            xtrace_meta_inst(meta));
    xtrace_appendf(line, sizeof(line), &pos, "\n");
    thread->next_pc = event->address + event->size;
    thread->has_next_pc = true;
    return fputs(line, out) == EOF ? -1 : 0;
  }

  if (event->type != XTRACE_EVENT_LOAD &&
      event->type != XTRACE_EVENT_STORE) {
    fprintf(stderr, "xtrace-decode: unknown event type %u\n", event->type);
    return -1;
  }

  const char *kind = event->type == XTRACE_EVENT_LOAD ? "LD" : "ST";
  const char *arrow = event->type == XTRACE_EVENT_LOAD ? "->" : "<-";
  if (fprintf(out, " - %s %" PRIu64 " M[%" PRIx64 "] %s ",
              kind, (uint64_t)event->meta * 8, event->address, arrow) < 0 ||
      xtrace_decoder_value(out, event) != 0 || fputc('\n', out) == EOF) {
    return -1;
  }
  return 0;
}

static int xtrace_decode_stream(FILE *input, FILE *output) {
  struct xtrace_file_header header;
  uint16_t endian = 1;
  bool ring_written = false;
  struct xtrace_decode_thread *threads = NULL;
  size_t thread_count = 0;
  int result = 1;

  if (fread(&header, sizeof(header), 1, input) != 1) {
    fprintf(stderr, "xtrace-decode: cannot read trace header\n");
    goto done;
  }
  if (memcmp(header.magic, XTRACE_FILE_MAGIC, sizeof(header.magic)) != 0 ||
      header.version != XTRACE_FILE_VERSION ||
      header.header_size != sizeof(header) ||
      header.event_size != sizeof(struct xtrace_event) ||
      header.pointer_size != sizeof(uintptr_t) ||
      (header.flags & ~(XTRACE_FILE_FLAG_CLOCK_TIMESTAMPS |
                        XTRACE_FILE_FLAG_BASE_OVERRIDE |
                        XTRACE_FILE_FLAG_CYCLE_TIMESTAMPS)) != 0 ||
      (header.flags & (XTRACE_FILE_FLAG_CLOCK_TIMESTAMPS |
                       XTRACE_FILE_FLAG_CYCLE_TIMESTAMPS)) ==
          (XTRACE_FILE_FLAG_CLOCK_TIMESTAMPS |
           XTRACE_FILE_FLAG_CYCLE_TIMESTAMPS) ||
      (header.timestamp_frequency_hz != 0 &&
       (header.flags & XTRACE_FILE_FLAG_CLOCK_TIMESTAMPS) == 0)) {
    fprintf(stderr, "xtrace-decode: unsupported or corrupt trace format\n");
    goto done;
  }
  if (header.byte_order != (*(uint8_t *)&endian == 1 ? 1 : 2)) {
    fprintf(stderr, "xtrace-decode: cross-endian decoding is not supported\n");
    goto done;
  }
  uint8_t decoder_arch = xtrace_decoder_arch();
  if (decoder_arch != XTRACE_ARCH_UNKNOWN && decoder_arch != header.arch) {
    fprintf(stderr,
            "xtrace-decode: trace architecture %u does not match decoder %u\n",
            header.arch, decoder_arch);
    goto done;
  }

  for (;;) {
    struct xtrace_block_header block;
    if (fread(&block, sizeof(block), 1, input) != 1) {
      fprintf(stderr, "xtrace-decode: truncated trace (missing EOF block)\n");
      goto done;
    }
    if (block.magic == XTRACE_EOF_MAGIC) {
      if (block.header_size != sizeof(block)) {
        fprintf(stderr, "xtrace-decode: corrupt EOF block\n");
        goto done;
      }
      break;
    }
    if (block.magic != XTRACE_BLOCK_MAGIC ||
        block.header_size != sizeof(block) ||
        block.event_count > XTRACE_EVENTS_PER_BLOCK ||
        block.thread_id > (1u << 20) ||
        block.raw_size != block.event_count * sizeof(struct xtrace_event) ||
        block.stored_size == 0 || block.stored_size > block.raw_size ||
        (block.flags & ~XTRACE_BLOCK_FLAG_ZSTD) != 0) {
      fprintf(stderr, "xtrace-decode: corrupt block header\n");
      goto done;
    }

    void *stored = malloc(block.stored_size);
    struct xtrace_event *events = malloc(block.raw_size);
    if (stored == NULL || events == NULL) {
      fprintf(stderr, "xtrace-decode: out of memory\n");
      free(stored);
      free(events);
      goto done;
    }
    if (fread(stored, block.stored_size, 1, input) != 1) {
      fprintf(stderr, "xtrace-decode: truncated event block\n");
      free(stored);
      free(events);
      goto done;
    }

    bool compressed = (block.flags & XTRACE_BLOCK_FLAG_ZSTD) != 0;
    if (compressed) {
      size_t decoded = ZSTD_decompress(events, block.raw_size, stored,
                                       block.stored_size);
      if (ZSTD_isError(decoded) || decoded != block.raw_size) {
        fprintf(stderr, "xtrace-decode: invalid zstd block\n");
        free(stored);
        free(events);
        goto done;
      }
    } else if (block.stored_size == block.raw_size) {
      memcpy(events, stored, block.raw_size);
    } else {
      fprintf(stderr, "xtrace-decode: block has unknown compression flags\n");
      free(stored);
      free(events);
      goto done;
    }
    free(stored);

    if (block.thread_id >= thread_count) {
      size_t new_count = (size_t)block.thread_id + 1;
      struct xtrace_decode_thread *new_threads =
          realloc(threads, new_count * sizeof(*new_threads));
      if (new_threads == NULL) {
        fprintf(stderr, "xtrace-decode: out of memory\n");
        free(events);
        goto done;
      }
      memset(new_threads + thread_count, 0,
             (new_count - thread_count) * sizeof(*new_threads));
      threads = new_threads;
      thread_count = new_count;
    }

    for (uint32_t i = 0; i < block.event_count; i++) {
      if (xtrace_decode_event(output, &header, &events[i],
                              &threads[block.thread_id],
                              &ring_written) != 0) {
        fprintf(stderr, "xtrace-decode: output write failed: %s\n",
                strerror(errno));
        free(events);
        goto done;
      }
    }
    free(events);
  }

  if (fputs("#eof\n", output) == EOF || fflush(output) != 0) {
    fprintf(stderr, "xtrace-decode: output write failed: %s\n",
            strerror(errno));
    goto done;
  }
  result = 0;

done:
  free(threads);
  return result;
}

int main(int argc, char **argv) {
  if (argc < 2 || argc > 3) {
    fprintf(stderr, "usage: %s INPUT.xtr [OUTPUT.txt]\n", argv[0]);
    return 2;
  }

  FILE *input = strcmp(argv[1], "-") == 0 ? stdin : fopen(argv[1], "rb");
  if (input == NULL) {
    fprintf(stderr, "xtrace-decode: cannot open %s: %s\n", argv[1],
            strerror(errno));
    return 1;
  }
  FILE *output = argc == 3 ? fopen(argv[2], "w") : stdout;
  if (output == NULL) {
    fprintf(stderr, "xtrace-decode: cannot open %s: %s\n", argv[2],
            strerror(errno));
    if (input != stdin) fclose(input);
    return 1;
  }
  setvbuf(input, NULL, _IOFBF, 1 << 20);
  setvbuf(output, NULL, _IOFBF, 1 << 20);

  int result = xtrace_decode_stream(input, output);
  if (input != stdin) fclose(input);
  if (output != stdout && fclose(output) != 0) result = 1;
  return result;
}
#endif /* XTRACE_DECODER */

#endif
