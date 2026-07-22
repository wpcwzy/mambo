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

  uintptr_t target = xtrace_has_base_override ? xtrace_base_override : pc;
  fprintf(xtrace_file, "ring %d, pc -> %" PRIxPTR "\n",
          xtrace_ring_level, target);
  xtrace_ring_written = true;
}

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
                                         uintptr_t pc, int inst) {
  switch ((riscv_instruction)inst) {
    case RISCV_C_ADDI4SPN: {
      unsigned int rd, nzuimm;
      riscv_c_addi4spn_decode_fields((uint16_t *)pc, &rd, &nzuimm);
      xtrace_appendf(buf, cap, pos, " %s, sp, %u",
                     xtrace_riscv_reg(rd + s0),
                     xtrace_riscv_c_addi4spn_imm(nzuimm));
      break;
    }
    case RISCV_C_FLD:
    case RISCV_C_LW:
    case RISCV_C_LD: {
      unsigned int rd, rs1, uimmhi, uimmlo;
      riscv_c_lw_decode_fields((uint16_t *)pc, &rd, &rs1, &uimmhi, &uimmlo);
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
      riscv_c_sw_decode_fields((uint16_t *)pc, &rs2, &rs1, &uimmhi, &uimmlo);
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
      riscv_c_lwsp_decode_fields((uint16_t *)pc, &rd, &uimmhi, &uimmlo);
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
      riscv_c_swsp_decode_fields((uint16_t *)pc, &rs2, &uimm);
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
      riscv_c_addi_decode_fields((uint16_t *)pc, &rd, &immhi, &immlo);
      xtrace_appendf(buf, cap, pos, " %s, %s, %" PRId32,
                     xtrace_riscv_reg(rd), xtrace_riscv_reg(rd),
                     xtrace_riscv_c_imm(immhi, immlo));
      break;
    }
    case RISCV_C_LI: {
      unsigned int rd, immhi, immlo;
      riscv_c_addi_decode_fields((uint16_t *)pc, &rd, &immhi, &immlo);
      xtrace_appendf(buf, cap, pos, " %s, %" PRId32,
                     xtrace_riscv_reg(rd),
                     xtrace_riscv_c_imm(immhi, immlo));
      break;
    }
    case RISCV_C_ADDI16SP: {
      unsigned int immhi, immlo;
      riscv_c_addi16sp_decode_fields((uint16_t *)pc, &immhi, &immlo);
      xtrace_appendf(buf, cap, pos, " sp, sp, %" PRId32,
                     xtrace_riscv_c_addi16sp_imm(immhi, immlo));
      break;
    }
    case RISCV_C_LUI: {
      unsigned int rd, immhi, immlo;
      riscv_c_lui_decode_fields((uint16_t *)pc, &rd, &immhi, &immlo);
      int32_t imm = sign_extend32(18, ((immhi << 5) | immlo) << 12);
      xtrace_appendf(buf, cap, pos, " %s, %" PRId32,
                     xtrace_riscv_reg(rd), imm);
      break;
    }
    case RISCV_C_SLLI: {
      unsigned int rs1_rd, shhi, shlo;
      riscv_c_slli_decode_fields((uint16_t *)pc, &rs1_rd, &shhi, &shlo);
      xtrace_appendf(buf, cap, pos, " %s, %s, %u",
                     xtrace_riscv_reg(rs1_rd), xtrace_riscv_reg(rs1_rd),
                     (shhi << 5) | shlo);
      break;
    }
    case RISCV_C_SRLI:
    case RISCV_C_SRAI: {
      unsigned int rs1_rd, shhi, shlo;
      riscv_c_slli_decode_fields((uint16_t *)pc, &rs1_rd, &shhi, &shlo);
      xtrace_appendf(buf, cap, pos, " %s, %s, %u",
                     xtrace_riscv_reg(rs1_rd + s0),
                     xtrace_riscv_reg(rs1_rd + s0),
                     (shhi << 5) | shlo);
      break;
    }
    case RISCV_C_ANDI: {
      unsigned int rs1_rd, immhi, immlo;
      riscv_c_andi_decode_fields((uint16_t *)pc, &rs1_rd, &immhi, &immlo);
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
      riscv_c_sub_decode_fields((uint16_t *)pc, &rs1_rd, &rs2);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s",
                     xtrace_riscv_reg(rs1_rd + s0),
                     xtrace_riscv_reg(rs1_rd + s0),
                     xtrace_riscv_reg(rs2 + s0));
      break;
    }
    case RISCV_C_ADD: {
      unsigned int rd, rs2;
      riscv_c_add_decode_fields((uint16_t *)pc, &rd, &rs2);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s",
                     xtrace_riscv_reg(rd),
                     xtrace_riscv_reg(rd), xtrace_riscv_reg(rs2));
      break;
    }
    case RISCV_C_MV: {
      unsigned int rd, rs2;
      riscv_c_add_decode_fields((uint16_t *)pc, &rd, &rs2);
      xtrace_appendf(buf, cap, pos, " %s, %s",
                     xtrace_riscv_reg(rd), xtrace_riscv_reg(rs2));
      break;
    }
    case RISCV_C_JR:
    case RISCV_C_JALR: {
      unsigned int rs1;
      riscv_c_jr_decode_fields((uint16_t *)pc, &rs1);
      xtrace_appendf(buf, cap, pos, " %s", xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_C_J:
    case RISCV_C_JAL: {
      unsigned int imm;
      riscv_c_j_decode_fields((uint16_t *)pc, &imm);
      int32_t offset = xtrace_riscv_c_j_offset(imm);
      xtrace_appendf(buf, cap, pos, " 0x%" PRIxPTR,
                     (uintptr_t)((intptr_t)pc + offset));
      break;
    }
    case RISCV_C_BEQZ:
    case RISCV_C_BNEZ: {
      unsigned int rs1, immhi, immlo;
      riscv_c_beqz_decode_fields((uint16_t *)pc, &rs1, &immhi, &immlo);
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
      riscv_lw_decode_fields((uint16_t *)pc, &rd, &rs1, &imm);
      xtrace_appendf(buf, cap, pos, " %s, %" PRId32 "(%s)",
                     xtrace_riscv_reg(rd), sign_extend32(12, imm),
                     xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_FLW:
    case RISCV_FLD: {
      unsigned int rd, rs1, imm;
      riscv_flw_decode_fields((uint16_t *)pc, &rd, &rs1, &imm);
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
      riscv_sw_decode_fields((uint16_t *)pc, &rs2, &rs1, &immhi, &immlo);
      int32_t offset = xtrace_riscv_store_offset(immhi, immlo);
      xtrace_appendf(buf, cap, pos, " %s, %" PRId32 "(%s)",
                     xtrace_riscv_reg(rs2), offset, xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_FSW:
    case RISCV_FSD: {
      unsigned int rs2, rs1, immhi, immlo;
      riscv_fsw_decode_fields((uint16_t *)pc, &rs2, &rs1, &immhi, &immlo);
      int32_t offset = xtrace_riscv_store_offset(immhi, immlo);
      xtrace_appendf(buf, cap, pos, " %s, %" PRId32 "(%s)",
                     xtrace_riscv_freg(rs2), offset, xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_FLH: {
      unsigned int offset, rs1, rd;
      riscv_flh_decode_fields((uint16_t *)pc, &offset, &rs1, &rd);
      xtrace_appendf(buf, cap, pos, " %s, %" PRId32 "(%s)",
                     xtrace_riscv_freg(rd), sign_extend32(12, offset),
                     xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_FSH: {
      unsigned int immhi, rs2, rs1, immlo;
      riscv_fsh_decode_fields((uint16_t *)pc, &immhi, &rs2, &rs1, &immlo);
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
      riscv_addi_decode_fields((uint16_t *)pc, &rd, &rs1, &imm);
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
      riscv_slli_decode_fields((uint16_t *)pc, &rd, &rs1, &shamt);
      xtrace_appendf(buf, cap, pos, " %s, %s, %u",
                     xtrace_riscv_reg(rd), xtrace_riscv_reg(rs1), shamt);
      break;
    }
    case RISCV_CSRRW:
    case RISCV_CSRRS:
    case RISCV_CSRRC: {
      unsigned int rd, csr, rs1;
      riscv_csrrw_decode_fields((uint16_t *)pc, &rd, &csr, &rs1);
      xtrace_appendf(buf, cap, pos, " %s, 0x%x, %s",
                     xtrace_riscv_reg(rd), csr, xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_CSRRWI:
    case RISCV_CSRRSI:
    case RISCV_CSRRCI: {
      unsigned int rd, csr, uimm;
      riscv_csrrwi_decode_fields((uint16_t *)pc, &rd, &csr, &uimm);
      xtrace_appendf(buf, cap, pos, " %s, 0x%x, %u",
                     xtrace_riscv_reg(rd), csr, uimm);
      break;
    }
    case RISCV_FENCE: {
      unsigned int fm, pred, succ;
      riscv_fence_decode_fields((uint16_t *)pc, &fm, &pred, &succ);
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
      riscv_add_decode_fields((uint16_t *)pc, &rd, &rs1, &rs2);
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
      riscv_add_uw_decode_fields((uint16_t *)pc, &rs2, &rs1, &rd);
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
      riscv_slli_uw_decode_fields((uint16_t *)pc, &shamt, &rs1, &rd);
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
      riscv_clz_decode_fields((uint16_t *)pc, &rs1, &rd);
      xtrace_appendf(buf, cap, pos, " %s, %s",
                     xtrace_riscv_reg(rd), xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_LUI:
    case RISCV_AUIPC: {
      unsigned int rd, imm;
      riscv_lui_decode_fields((uint16_t *)pc, &rd, &imm);
      xtrace_appendf(buf, cap, pos, " %s, 0x%x",
                     xtrace_riscv_reg(rd), imm);
      break;
    }
    case RISCV_LR_W:
    case RISCV_LR_D: {
      unsigned int aq, rl, rd, rs1;
      riscv_lr_w_decode_fields((uint16_t *)pc, &aq, &rl, &rd, &rs1);
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
      riscv_sc_w_decode_fields((uint16_t *)pc, &aq, &rl, &rd, &rs2, &rs1);
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
      riscv_fmadd_s_decode_fields((uint16_t *)pc, &rd, &rs1, &rs2, &rs3, &rm);
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
      riscv_fmadd_h_decode_fields((uint16_t *)pc, &rs3, &rs2, &rs1, &rm, &rd);
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
      riscv_fadd_s_decode_fields((uint16_t *)pc, &rd, &rs1, &rs2, &rm);
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
      riscv_fadd_h_decode_fields((uint16_t *)pc, &rs2, &rs1, &rm, &rd);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s, %s",
                     xtrace_riscv_freg(rd), xtrace_riscv_freg(rs1),
                     xtrace_riscv_freg(rs2), xtrace_riscv_rm(rm));
      break;
    }
    case RISCV_FSQRT_S:
    case RISCV_FSQRT_D: {
      unsigned int rd, rs1, rm;
      riscv_fsqrt_s_decode_fields((uint16_t *)pc, &rd, &rs1, &rm);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s",
                     xtrace_riscv_freg(rd), xtrace_riscv_freg(rs1),
                     xtrace_riscv_rm(rm));
      break;
    }
    case RISCV_FSQRT_H: {
      unsigned int rs1, rm, rd;
      riscv_fsqrt_h_decode_fields((uint16_t *)pc, &rs1, &rm, &rd);
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
      riscv_fsgnj_s_decode_fields((uint16_t *)pc, &rd, &rs1, &rs2);
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
      riscv_fsgnj_h_decode_fields((uint16_t *)pc, &rs2, &rs1, &rd);
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
      riscv_feq_s_decode_fields((uint16_t *)pc, &rd, &rs1, &rs2);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s",
                     xtrace_riscv_reg(rd), xtrace_riscv_freg(rs1),
                     xtrace_riscv_freg(rs2));
      break;
    }
    case RISCV_FEQ_H:
    case RISCV_FLT_H:
    case RISCV_FLE_H: {
      unsigned int rs2, rs1, rd;
      riscv_feq_h_decode_fields((uint16_t *)pc, &rs2, &rs1, &rd);
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
      riscv_fmv_x_w_decode_fields((uint16_t *)pc, &rd, &rs1);
      xtrace_appendf(buf, cap, pos, " %s, %s",
                     xtrace_riscv_reg(rd), xtrace_riscv_freg(rs1));
      break;
    }
    case RISCV_FCLASS_H:
    case RISCV_FMV_X_H: {
      unsigned int rs1, rd;
      riscv_fmv_x_h_decode_fields((uint16_t *)pc, &rs1, &rd);
      xtrace_appendf(buf, cap, pos, " %s, %s",
                     xtrace_riscv_reg(rd), xtrace_riscv_freg(rs1));
      break;
    }
    case RISCV_FMV_W_X:
    case RISCV_FMV_D_X: {
      unsigned int rd, rs1;
      riscv_fmv_w_x_decode_fields((uint16_t *)pc, &rd, &rs1);
      xtrace_appendf(buf, cap, pos, " %s, %s",
                     xtrace_riscv_freg(rd), xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_FMV_H_X: {
      unsigned int rs1, rd;
      riscv_fmv_h_x_decode_fields((uint16_t *)pc, &rs1, &rd);
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
      riscv_fcvt_w_s_decode_fields((uint16_t *)pc, &rd, &rs1, &rm);
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
      riscv_fcvt_w_h_decode_fields((uint16_t *)pc, &rs1, &rm, &rd);
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
      riscv_fcvt_s_w_decode_fields((uint16_t *)pc, &rd, &rs1, &rm);
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
      riscv_fcvt_h_w_decode_fields((uint16_t *)pc, &rs1, &rm, &rd);
      xtrace_appendf(buf, cap, pos, " %s, %s, %s",
                     xtrace_riscv_freg(rd), xtrace_riscv_reg(rs1),
                     xtrace_riscv_rm(rm));
      break;
    }
    case RISCV_FCVT_S_D:
    case RISCV_FCVT_D_S: {
      unsigned int rd, rs1, rm;
      riscv_fcvt_s_d_decode_fields((uint16_t *)pc, &rd, &rs1, &rm);
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
      riscv_fcvt_s_h_decode_fields((uint16_t *)pc, &rs1, &rm, &rd);
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
      riscv_cbo_clean_decode_fields((uint16_t *)pc, &rs1);
      xtrace_appendf(buf, cap, pos, " (%s)", xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_PREFETCH_I:
    case RISCV_PREFETCH_R:
    case RISCV_PREFETCH_W: {
      unsigned int offset, rs1;
      riscv_prefetch_i_decode_fields((uint16_t *)pc, &offset, &rs1);
      xtrace_appendf(buf, cap, pos, " %u(%s)",
                     offset, xtrace_riscv_reg(rs1));
      break;
    }
    case RISCV_V_OP: {
      unsigned int funct, rs1_vs1, funct3, rd_vd;
      riscv_v_op_decode_fields((uint16_t *)pc, &funct, &rs1_vs1, &funct3, &rd_vd);
      xtrace_appendf(buf, cap, pos, " v%u, rs1/vs1=%u, funct=0x%x, funct3=0x%x",
                     rd_vd, rs1_vs1, funct, funct3);
      break;
    }
    case RISCV_V_LOAD_B:
    case RISCV_V_LOAD_H:
    case RISCV_V_LOAD_W:
    case RISCV_V_LOAD_D: {
      unsigned int lumop, rs1, vd;
      riscv_v_load_b_decode_fields((uint16_t *)pc, &lumop, &rs1, &vd);
      xtrace_appendf(buf, cap, pos, " v%u, (%s), lumop=0x%x",
                     vd, xtrace_riscv_reg(rs1), lumop);
      break;
    }
    case RISCV_V_STORE_B:
    case RISCV_V_STORE_H:
    case RISCV_V_STORE_W:
    case RISCV_V_STORE_D: {
      unsigned int sumop, rs1, vs3;
      riscv_v_store_b_decode_fields((uint16_t *)pc, &sumop, &rs1, &vs3);
      xtrace_appendf(buf, cap, pos, " v%u, (%s), sumop=0x%x",
                     vs3, xtrace_riscv_reg(rs1), sumop);
      break;
    }
    case RISCV_V_AMO_B:
    case RISCV_V_AMO_H:
    case RISCV_V_AMO_W:
    case RISCV_V_AMO_D: {
      unsigned int amoop, rs1, vd;
      riscv_v_amo_b_decode_fields((uint16_t *)pc, &amoop, &rs1, &vd);
      xtrace_appendf(buf, cap, pos, " v%u, (%s), amoop=0x%x",
                     vd, xtrace_riscv_reg(rs1), amoop);
      break;
    }
    case RISCV_JAL: {
      unsigned int rd, imm;
      riscv_jal_decode_fields((uint16_t *)pc, &rd, &imm);
      int32_t offset = xtrace_riscv_jal_offset(imm);
      xtrace_appendf(buf, cap, pos, " %s, 0x%" PRIxPTR,
                     xtrace_riscv_reg(rd),
                     (uintptr_t)((intptr_t)pc + offset));
      break;
    }
    case RISCV_JALR: {
      unsigned int rd, rs1, imm;
      riscv_jalr_decode_fields((uint16_t *)pc, &rd, &rs1, &imm);
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
      riscv_blt_decode_fields((uint16_t *)pc, &rs1, &rs2, &immhi, &immlo);
      int32_t offset = xtrace_riscv_branch_offset(immhi, immlo);
      xtrace_appendf(buf, cap, pos, " %s, %s, 0x%" PRIxPTR,
                     xtrace_riscv_reg(rs1), xtrace_riscv_reg(rs2),
                     (uintptr_t)((intptr_t)pc + offset));
      break;
    }
    case RISCV_BRANCH: {
      unsigned int funct3, rs1, rs2, immhi, immlo;
      riscv_branch_decode_fields((uint16_t *)pc, &funct3, &rs1, &rs2,
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
    fprintf(xtrace_file, " - LD %" PRIuPTR " M[%" PRIxPTR "] -> ",
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
  fprintf(xtrace_file, " - ST %" PRIuPTR " M[%" PRIxPTR "] <- ",
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
