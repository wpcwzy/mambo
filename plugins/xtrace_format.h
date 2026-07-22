#ifndef MAMBO_XTRACE_FORMAT_H
#define MAMBO_XTRACE_FORMAT_H

#include <stdint.h>

#define XTRACE_FILE_MAGIC "MXTRACE\0"
#define XTRACE_FILE_VERSION 1
#define XTRACE_BLOCK_MAGIC 0x4b4c4258u /* XBLK */
#define XTRACE_EOF_MAGIC 0x464f4558u   /* XEOF */

#define XTRACE_FILE_FLAG_CLOCK_TIMESTAMPS (1u << 0)
#define XTRACE_FILE_FLAG_BASE_OVERRIDE (1u << 1)
#define XTRACE_FILE_FLAG_CYCLE_TIMESTAMPS (1u << 2)
#define XTRACE_BLOCK_FLAG_ZSTD (1u << 0)
#define XTRACE_EVENT_FLAG_VALUE_TRUNCATED (1u << 0)
#define XTRACE_EVENT_FLAG_TIMESTAMP_SAMPLE (1u << 1)

enum xtrace_arch {
  XTRACE_ARCH_UNKNOWN = 0,
  XTRACE_ARCH_ARM = 1,
  XTRACE_ARCH_AARCH64 = 2,
  XTRACE_ARCH_RISCV64 = 3,
};

enum xtrace_event_type {
  XTRACE_EVENT_INST = 1,
  XTRACE_EVENT_LOAD = 2,
  XTRACE_EVENT_STORE = 3,
};

/* All fields are written in the target's native byte order. */
struct xtrace_file_header {
  char magic[8];
  uint16_t version;
  uint16_t header_size;
  uint16_t event_size;
  uint8_t byte_order;
  uint8_t pointer_size;
  uint8_t arch;
  uint8_t flags;
  uint16_t reserved0;
  int32_t ring_level;
  uint32_t compression_level;
  uint32_t reserved1;
  uint64_t base_override;
  uint64_t timestamp_frequency_hz;
  uint64_t reserved[2];
};

struct xtrace_block_header {
  uint32_t magic;
  uint32_t header_size;
  uint32_t thread_id;
  uint32_t event_count;
  uint32_t raw_size;
  uint32_t stored_size;
  uint32_t flags;
  uint32_t reserved;
};

/*
 * Fixed-size records make the hot path a few stores. Zstd removes the repeated
 * PCs, encodings and zero fields when a full block is flushed.
 */
struct xtrace_event {
  uint64_t address;
  uint64_t data_lo;
  uint64_t data_hi;
  uint32_t meta;
  uint16_t size;
  uint8_t type;
  uint8_t flags;
};

typedef char xtrace_header_size_must_be_64[
    sizeof(struct xtrace_file_header) == 64 ? 1 : -1];
typedef char xtrace_block_size_must_be_32[
    sizeof(struct xtrace_block_header) == 32 ? 1 : -1];
typedef char xtrace_event_size_must_be_32[
    sizeof(struct xtrace_event) == 32 ? 1 : -1];

#endif
