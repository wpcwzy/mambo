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

#ifdef PLUGINS_NEW

#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../plugins.h"
#include "xtrace_disasm.h"

#define XTRACE_DEFAULT_FILE "pinatrace.out"
#define XTRACE_INFO_LOAD 1
#define XTRACE_INFO_STORE 2
#define XTRACE_INFO_SIZE_SHIFT 2
#define XTRACE_INST_META_INST_BITS 24
#define XTRACE_INST_META_INST_MASK ((uintptr_t)((1u << XTRACE_INST_META_INST_BITS) - 1))
#define XTRACE_MAX_BYTE_VALUE 16
#define XTRACE_PAGE_SIZE 4096

struct xtrace_thread {
  uintptr_t store_addr;
  uintptr_t store_info;
  bool store_pending;
};

static FILE *xtrace_file;
static bool xtrace_close_file;
static bool xtrace_ring_written;
static bool xtrace_has_base_override;
static uintptr_t xtrace_base_override;
static int xtrace_ring_level = 3;
static uint64_t xtrace_start_stamp;

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

static uint64_t xtrace_read_stamp(void) {
  struct timespec ts;
#ifdef CLOCK_MONOTONIC_RAW
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#else
  clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
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

static int xtrace_meta_inst_type(uintptr_t meta) {
  return (int)(meta >> XTRACE_INST_META_INST_BITS);
}

static int xtrace_meta_inst(uintptr_t meta) {
  uintptr_t inst = meta & XTRACE_INST_META_INST_MASK;
  return inst == XTRACE_INST_META_INST_MASK ? -1 : (int)inst;
}

static void xtrace_parse_config(void) {
  const char *ring = getenv("MAMBO_XTRACE_RING");
  if (ring != NULL && ring[0] != '\0') {
    xtrace_ring_level = atoi(ring);
  }

  const char *base = getenv("MAMBO_XTRACE_BASE");
  if (base != NULL && base[0] != '\0') {
    xtrace_base_override = (uintptr_t)strtoull(base, NULL, 0);
    xtrace_has_base_override = true;
  }
}

static void xtrace_open_file(void) {
  const char *path = getenv("MAMBO_XTRACE_FILE");
  if (path == NULL || path[0] == '\0') {
    path = XTRACE_DEFAULT_FILE;
  }

  if (strcmp(path, "-") == 0) {
    xtrace_file = stderr;
    xtrace_close_file = false;
  } else {
    xtrace_file = fopen(path, "w");
    xtrace_close_file = true;
  }

  if (xtrace_file == NULL) {
    fprintf(stderr, "xtrace: failed to open %s, falling back to stderr\n", path);
    xtrace_file = stderr;
    xtrace_close_file = false;
  }

  setvbuf(xtrace_file, NULL, _IOFBF, 1 << 20);
}

static void xtrace_print_ring_line(uintptr_t pc) {
  if (xtrace_ring_written) {
    return;
  }

  uintptr_t base = xtrace_has_base_override
                     ? xtrace_base_override
                     : pc & ~((uintptr_t)XTRACE_PAGE_SIZE - 1);
  fprintf(xtrace_file, "ring %d %" PRIxPTR "\n", xtrace_ring_level, base);
  xtrace_ring_written = true;
}

static void xtrace_format_bytes(char *buf, size_t cap, size_t *pos,
                                uintptr_t encoding, uintptr_t inst_len) {
  if (inst_len == 0 || inst_len > sizeof(encoding)) {
    xtrace_appendf(buf, cap, pos, "??");
    return;
  }

  for (uintptr_t i = 0; i < inst_len; i++) {
    if (i != 0) {
      xtrace_appendf(buf, cap, pos, " ");
    }
    xtrace_appendf(buf, cap, pos, "%02" PRIxPTR,
                   (encoding >> (i * 8)) & 0xff);
  }
}

static void xtrace_print_mem_value(uintptr_t addr, uintptr_t size) {
  if (size == 0) {
    fprintf(xtrace_file, "?");
  } else if (size <= sizeof(uint64_t)) {
    uint64_t value = 0;
    memcpy(&value, (void *)addr, size);
    fprintf(xtrace_file, "0x%" PRIx64, value);
  } else {
    unsigned char bytes[XTRACE_MAX_BYTE_VALUE];
    uintptr_t bytes_to_print = size;
    if (bytes_to_print > XTRACE_MAX_BYTE_VALUE) {
      bytes_to_print = XTRACE_MAX_BYTE_VALUE;
    }

    memcpy(bytes, (void *)addr, bytes_to_print);
    fprintf(xtrace_file, "0x");
    for (uintptr_t i = 0; i < bytes_to_print; i++) {
      fprintf(xtrace_file, "%02x", bytes[i]);
    }
    if (bytes_to_print < size) {
      fprintf(xtrace_file, "...");
    }
  }
}

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

static void xtrace_append_riscv_operands(char *buf, size_t cap, size_t *pos,
                                         uintptr_t pc, int inst) {
  switch ((riscv_instruction)inst) {
    case RISCV_LB:
    case RISCV_LH:
    case RISCV_LW:
    case RISCV_LD:
    case RISCV_LBU:
    case RISCV_LHU:
    case RISCV_LWU: {
      unsigned int rd, rs1, imm;
      riscv_lw_decode_fields((uint16_t *)pc, &rd, &rs1, &imm);
      xtrace_appendf(buf, cap, pos, " %s, %" PRId32 "(%s)",
                     xtrace_riscv_reg(rd), sign_extend32(12, imm),
                     xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_SB:
    case RISCV_SH:
    case RISCV_SW:
    case RISCV_SD: {
      unsigned int rs2, rs1, immhi, immlo;
      riscv_sw_decode_fields((uint16_t *)pc, &rs2, &rs1, &immhi, &immlo);
      int32_t offset = sign_extend32(12, (immhi << 5) | immlo);
      xtrace_appendf(buf, cap, pos, " %s, %" PRId32 "(%s)",
                     xtrace_riscv_reg(rs2), offset, xtrace_riscv_reg(rs1));
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
    xtrace_append_riscv_operands(buf, cap, pos, pc, inst);
  }
#endif
}

void xtrace_record_inst(uintptr_t pc, uintptr_t encoding, uintptr_t inst_len,
                        uintptr_t meta) {
  char line[256];
  size_t pos = 0;
  int inst_type = xtrace_meta_inst_type(meta);
  int inst = xtrace_meta_inst(meta);

  xtrace_print_ring_line(pc);
  xtrace_appendf(line, sizeof(line), &pos, "%" PRIxPTR " @%" PRIu64 ": ",
                 pc, xtrace_timestamp());
  xtrace_format_bytes(line, sizeof(line), &pos, encoding, inst_len);
  xtrace_appendf(line, sizeof(line), &pos, "  ");
  xtrace_format_inst_text(line, sizeof(line), &pos, pc, encoding,
                          inst_type, inst);
  xtrace_appendf(line, sizeof(line), &pos, "\n");
  fputs(line, xtrace_file);
}

void xtrace_record_access_pre(struct xtrace_thread *thread, uintptr_t pc,
                              uintptr_t addr, uintptr_t info) {
  (void)pc;
  uintptr_t size = info >> XTRACE_INFO_SIZE_SHIFT;

  if (info & XTRACE_INFO_LOAD) {
    fprintf(xtrace_file, " - LD %" PRIuPTR " M[0x%" PRIxPTR "] -> ",
            size * 8, addr);
    xtrace_print_mem_value(addr, size);
    fprintf(xtrace_file, "\n");
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
  fprintf(xtrace_file, " - ST %" PRIuPTR " M[0x%" PRIxPTR "] <- ",
          size * 8, thread->store_addr);
  xtrace_print_mem_value(thread->store_addr, size);
  fprintf(xtrace_file, "\n");

  thread->store_pending = false;
}

int xtrace_pre_inst_handler(mambo_context *ctx) {
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
  emit_set_reg_ptr(ctx, a0, (void *)xtrace_source_addr(ctx));
  emit_set_reg(ctx, a1, xtrace_inst_encoding(ctx));
  emit_set_reg(ctx, a2, mambo_get_inst_len(ctx));
  emit_set_reg(ctx, a3, xtrace_inst_meta(ctx));
  ret = emit_safe_fcall(ctx, xtrace_record_inst, 4);
  assert(ret == 0);
  emit_pop(ctx, (1 << a0) | (1 << a1) | (1 << a2) | (1 << a3) | (1 << lr));
#else
  emit_push(ctx, (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << lr));
  emit_set_reg_ptr(ctx, 0, (void *)xtrace_source_addr(ctx));
  emit_set_reg(ctx, 1, xtrace_inst_encoding(ctx));
  emit_set_reg(ctx, 2, mambo_get_inst_len(ctx));
  emit_set_reg(ctx, 3, xtrace_inst_meta(ctx));
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

int xtrace_pre_thread_handler(mambo_context *ctx) {
  struct xtrace_thread *thread = mambo_alloc(ctx, sizeof(*thread));
  assert(thread != NULL);

  thread->store_pending = false;

  int ret = mambo_set_thread_plugin_data(ctx, thread);
  assert(ret == MAMBO_SUCCESS);

  return 0;
}

int xtrace_post_thread_handler(mambo_context *ctx) {
  struct xtrace_thread *thread = mambo_get_thread_plugin_data(ctx);
  mambo_free(ctx, thread);

  return 0;
}

int xtrace_exit_handler(mambo_context *ctx) {
  (void)ctx;
  fprintf(xtrace_file, "#eof\n");
  fflush(xtrace_file);

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

  mambo_register_pre_thread_cb(ctx, &xtrace_pre_thread_handler);
  mambo_register_post_thread_cb(ctx, &xtrace_post_thread_handler);
  mambo_register_pre_inst_cb(ctx, &xtrace_pre_inst_handler);
  mambo_register_post_inst_cb(ctx, &xtrace_post_inst_handler);
  mambo_register_exit_cb(ctx, &xtrace_exit_handler);
}

#endif
