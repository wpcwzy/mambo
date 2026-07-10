/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2017 The University of Manchester

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

#include "mtrace.h"

#if defined(__arm__) || defined(__aarch64__)

#ifdef __arm__
.syntax unified
#endif

.global mtrace_buf_write // (value, info, &buf_ptr.entries[0])
.func
.type mtrace_buf_write, %function

#ifdef __arm__
.thumb_func
mtrace_buf_write:
  PUSH {R3, R4}
  LDR R3, [R2, #-4]
  ADD R4, R2, R3, LSL #3
  STRD R0, R1, [R4]
  ADD R3, R3, #1
  STR R3, [R2, #-4]
  SUB R3, R3, #BUFLEN
  CBZ R3, call
  POP {R3, R4}
  BX LR

call:
  PUSH {R0-R2, R5-R6, R9, R12, LR}
  VPUSH {D16-D31}
  VPUSH {D0-D7}
  MRS R4, CPSR
  VMRS R5, FPSCR

  SUB R0, R2, #4

  MOV R6, SP
  BIC R2, R6, #7
  MOV SP, R2
  LDR R1, =mtrace_print_buf
  BLX R1
  MOV SP, R6

  MSR CPSR, R4
  VMSR FPSCR, R5
  VPOP {D0-D7}
  VPOP {D16-D31}
  POP {R0-R2, R5-R6, R9, R12, LR}
  POP {R3 - R4}
  BX LR
#endif

#ifdef __aarch64__
mtrace_buf_write:
  STP X3, X4, [SP, #-16]!
  LDR W3, [X2, #-8]
  ADD X4, X2, W3, UXTW #4
  STP X0, X1, [X4]

  ADD W3, W3, #1
  STR W3, [X2, #-8]
  SUB W3, W3, #BUFLEN
  CBZ W3, call
  LDP X3, X4, [SP], #16
  RET

call:
  STP X29, X30, [SP, #-16]!

  BL push_x4_x21
  MRS X19, NZCV
  MRS X20, FPCR
  MRS X21, FPSR
  BL push_neon

  SUB X0, X2, #8
  LDR X1, =mtrace_print_buf
  BLR X1

  BL pop_neon
  MSR NZCV, X19
  MSR FPCR, X20
  MSR FPSR, X21
  BL pop_x4_x21

  LDP X3, X4, [SP, #16]
  LDP X29, X30, [SP], #32
  RET
#endif

.endfunc
#endif

#if defined(__riscv) && __riscv_xlen == 64

.global mtrace_buf_write
.func
.type mtrace_buf_write, %function

mtrace_buf_write:
  addi sp, sp, -16
  sd t0, 0(sp)
  sd t1, 8(sp)

  lwu t0, -8(a2)
  slli t1, t0, 4
  add t1, a2, t1
  sd a0, 0(t1)
  sd a1, 8(t1)

  addiw t0, t0, 1
  sw t0, -8(a2)

  li t1, BUFLEN
  beq t0, t1, call

  ld t0, 0(sp)
  ld t1, 8(sp)
  addi sp, sp, 16
  ret

call:
  addi sp, sp, -16
  sd ra, 0(sp)
  sd s0, 8(sp)

  // Save caller-saved GP registers (a3-a7, t0-t6)
  addi sp, sp, -(12 * 8)
  sd a3,  0 * 8(sp)
  sd a4,  1 * 8(sp)
  sd a5,  2 * 8(sp)
  sd a6,  3 * 8(sp)
  sd a7,  4 * 8(sp)
  sd t0,  5 * 8(sp)
  sd t1,  6 * 8(sp)
  sd t2,  7 * 8(sp)
  sd t3,  8 * 8(sp)
  sd t4,  9 * 8(sp)
  sd t5, 10 * 8(sp)
  sd t6, 11 * 8(sp)

  // Save s1, s2 for FP status storage
  addi sp, sp, -16
  sd s1, 0(sp)
  sd s2, 8(sp)

  // Save FP registers (only if FP is available)
#if __riscv_flen
  jal ra, push_fp
#endif

  // Save FP status registers
  frcsr s0
  frflags s1
  frrm s2

  // Call mtrace_print_buf(&trace->len)
  addi a0, a2, -8
  la a1, mtrace_print_buf
  jalr ra, a1

  // Restore FP status registers
  fscsr s0
  fsflags s1
  fsrm s2

  // Restore FP registers
#if __riscv_flen
  jal ra, pop_fp
#endif

  // Restore s1, s2
  ld s1, 0(sp)
  ld s2, 8(sp)
  addi sp, sp, 16

  // Restore caller-saved GP registers
  ld a3,  0 * 8(sp)
  ld a4,  1 * 8(sp)
  ld a5,  2 * 8(sp)
  ld a6,  3 * 8(sp)
  ld a7,  4 * 8(sp)
  ld t0,  5 * 8(sp)
  ld t1,  6 * 8(sp)
  ld t2,  7 * 8(sp)
  ld t3,  8 * 8(sp)
  ld t4,  9 * 8(sp)
  ld t5, 10 * 8(sp)
  ld t6, 11 * 8(sp)
  addi sp, sp, (12 * 8)

  // Restore ra, s0 and original t0, t1 from fast-path frame
  ld ra, 0(sp)
  ld s0, 8(sp)
  ld t0, 16(sp)
  ld t1, 24(sp)
  addi sp, sp, 32
  ret

.endfunc
#endif