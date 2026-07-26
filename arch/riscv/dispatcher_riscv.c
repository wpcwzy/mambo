/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2020 Guillermo Callaghan <guillermocallaghan at hotmail dot com>
  Copyright 2020-2022 The University of Manchester

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

#include <assert.h>
#ifdef DBM_JUMP_TRAMPOLINE_DEBUG
#include <stdio.h>
#endif

#include "dbm.h"
#include "scanner_common.h"
#include "pie/pie-riscv-encoder.h"

#ifdef DBM_JUMP_TRAMPOLINES
#define RISCV_JAL_RANGE (1024 * 1024)
#define RISCV_TRAMPOLINE_MAX_HOPS 8
#endif

/*
      Algorithm for linking:
        * look up both the target and the fallthrough
        * if lookup(target) fits within +-4KiB
          * BRANCH lookup(target)
          * if lookup(fallthrough) JA/{PUSH + JALR} lookup(fallthrough)
          * return
        * else if lookup(fallthrough) fits within +-4KiB
          * BRANCH(inv) lookup(target)
          * if lookup(fallthrough) JA/{PUSH + JALR} lookup(target)
          * return
        ---
        [not handled at the moment]
        * else if lookup(target) > +-1MiB && lookup(fallthrough) && lookup(fallthrough) > +- 1MiB
          * PUSH {a0, a1}
          * BRANCH invert(cond)
          * JALR lookup(target)
          * JALR lookup(fallthrough)
          * return
        ---
        * else -
          * BRANCH invert(cond)
          * JA/{PUSH + JALR} lookup(target)
          * if lookup(fallthrough) JA/{PUSH + JALR} lookup(fallthrough)

       Target/fallthrough linked, within +/-4KiB
         BRANCH translation target+12
         skip:

       Target linked, within +/-1MB
         BRANCH skip
         JAL zero, translation target+12
         skip:

       Target linked, range greater than +/-1MB
         BRANCH skip                                       4b
         ADDI sp, sp, -16                                  2/4b
         SD a0, 0(sp)                                      2/4b
         SD a1, 8(sp)                                      2/4b
         AUIPC a0, (target offset + 0x800) >> 12           4b
         JALR zero, a0, translation target offset from a0  4b
         skip:                                             18b(c) / 24b

      Both paths linked, both greater than +/-1MB
         ADDI sp, sp, -16
         SD a0, 0(sp)
         SD a1, 8(sp)
         BRANCH skip
         AUIPC a0, (target offset + 0x800) >> 12
         JALR zero, a0, translation target offset from a0
         skip:
         AUIPC a0, (fallthrough offset + 0x800) >> 12
         JALR zero, a0, translation fallthrough offset from a0
*/

#ifdef DBM_JUMP_TRAMPOLINES
static bool riscv_jal_can_reach(uintptr_t from, uintptr_t target) {
  intptr_t offset = (intptr_t)target - (intptr_t)from;
  return !(offset & 1) && offset >= -RISCV_JAL_RANGE && offset < RISCV_JAL_RANGE;
}

static uint64_t riscv_address_distance(uintptr_t a, uintptr_t b) {
  return a >= b ? a - b : b - a;
}

static dbm_code_cache_meta *riscv_find_trampoline_slot(dbm_thread *thread_data,
                                                        uintptr_t source,
                                                        uintptr_t target,
                                                        uint16_t **slot_addr) {
  bool forward = source < target;
  dbm_code_cache_meta *best = NULL;
  uintptr_t best_addr = 0;

  for (int i = trampolines_size_bbs; i < thread_data->free_block; i++) {
    dbm_code_cache_meta *meta = &thread_data->code_cache_meta[i];
    if (meta->trampoline_addr == NULL ||
        meta->trampoline_slots_used >= RISCV_TRAMPOLINE_SLOTS) {
      continue;
    }

    uintptr_t candidate = (uintptr_t)(meta->trampoline_addr +
                          meta->trampoline_slots_used * 2);
    bool between = forward ? candidate > source && candidate < target
                           : candidate < source && candidate > target;
    if (!between || !riscv_jal_can_reach(candidate, target)) {
      continue;
    }

    if (best == NULL || (forward ? candidate < best_addr : candidate > best_addr)) {
      best = meta;
      best_addr = candidate;
    }
  }

  if (best != NULL) {
    *slot_addr = (uint16_t *)best_addr;
  }
  return best;
}

static int riscv_try_jump_trampolines(dbm_thread *thread_data,
                                      uint16_t *source, uintptr_t target) {
  if (riscv_address_distance((uintptr_t)source, target) >=
      RISCV_TRAMPOLINE_MAX_DISTANCE) {
#ifdef DBM_JUMP_TRAMPOLINE_DEBUG
    fprintf(stderr, "MAMBO: jump from 0x%" PRIxPTR " to 0x%" PRIxPTR
                    " exceeds jump-trampoline distance; using JALR\n",
            (uintptr_t)source, target);
#endif
    return -1;
  }

  dbm_code_cache_meta *slot_meta[RISCV_TRAMPOLINE_MAX_HOPS];
  uint16_t *slot_addr[RISCV_TRAMPOLINE_MAX_HOPS];
  int slots = 0;
  uintptr_t next_target = target;

  while (!riscv_jal_can_reach((uintptr_t)source, next_target)) {
    if (slots >= RISCV_TRAMPOLINE_MAX_HOPS) {
      return -1;
    }

    slot_meta[slots] = riscv_find_trampoline_slot(thread_data,
                                                   (uintptr_t)source,
                                                   next_target,
                                                   &slot_addr[slots]);
    if (slot_meta[slots] == NULL) {
      return -1;
    }
    next_target = (uintptr_t)slot_addr[slots++];
  }

  for (int i = 0; i < slots; i++) {
    uint16_t *write_p = slot_addr[i];
    assert(riscv_jal_helper(&write_p, i == 0 ? target : (uintptr_t)slot_addr[i - 1],
                            zero) == 0);
    slot_meta[i]->trampoline_slots_used++;
    __clear_cache(slot_addr[i], write_p);
  }

  uint16_t *write_p = source;
  assert(riscv_jal_helper(&write_p, next_target, zero) == 0);
#ifdef DBM_JUMP_TRAMPOLINE_DEBUG
  thread_data->jump_trampoline_links++;
  fprintf(stderr, "MAMBO: linked 0x%" PRIxPTR " to 0x%" PRIxPTR
                  " through %d jump trampoline%s\n",
          (uintptr_t)source, target, slots, slots == 1 ? "" : "s");
#endif
  return 0;
}
#endif

static void riscv_pad_direct_link(uint16_t **o_write_p) {
#ifdef DBM_TRACES
  uint16_t *write_p = *o_write_p;
  for (int i = 0; i < 4; i++) {
    riscv_addi(&write_p, zero, zero, 0); // NOP
    write_p += 2;
  }
  *o_write_p = write_p;
#endif
}

int riscv_link_to(dbm_thread *thread_data, uint16_t **o_write_p, uintptr_t target) {
  uint16_t *write_p = *o_write_p;
  int ret = riscv_jal_helper(&write_p, target+6, zero);
  if (ret != 0) {
#ifdef DBM_JUMP_TRAMPOLINES
    if (riscv_try_jump_trampolines(thread_data, *o_write_p, target + 6) == 0) {
      write_p = *o_write_p + 2;
      riscv_pad_direct_link(&write_p);
      ret = 0;
    } else
#endif
    {
      riscv_push(&write_p, (1 << a0) | (1 << a1));
      ret = riscv_jalr_helper(&write_p, target, zero, a0);
    }
  } else {
    riscv_pad_direct_link(&write_p);
  }
  record_cc_link(thread_data, (uintptr_t)*o_write_p, target);
  *o_write_p = write_p;
  return ret;
}

void riscv_link_branch(dbm_thread *thread_data, int bb_id, uintptr_t target) {
  dbm_code_cache_meta *bb_meta = &thread_data->code_cache_meta[bb_id];
  uint16_t *write_p = bb_meta->exit_branch_addr;

  uintptr_t target_tpc = cc_lookup(thread_data, bb_meta->branch_taken_addr);
  int target_in_cc = target_tpc != UINT_MAX;
  uintptr_t fallthrough_tpc = cc_lookup(thread_data, bb_meta->branch_skipped_addr);
  int fallthrough_in_cc = fallthrough_tpc != UINT_MAX;
  assert(target_in_cc || fallthrough_in_cc);

  if (target_in_cc &&
      riscv_branch_helper(&write_p, target_tpc+6, bb_meta->rs1, bb_meta->rs2,
      bb_meta->branch_condition) == 0) {
    record_cc_link(thread_data, (uintptr_t)(write_p-2), target_tpc+6);
    if (fallthrough_in_cc) {
      int ret = riscv_link_to(thread_data, &write_p, fallthrough_tpc);
      assert(ret == 0);
    }
  } else if (fallthrough_in_cc &&
      riscv_branch_helper(&write_p, target_tpc+6, bb_meta->rs1, bb_meta->rs2,
      invert_cond(bb_meta->branch_condition)) == 0) {
    record_cc_link(thread_data, (uintptr_t)(write_p-2), target_tpc+6);
    if (target_in_cc) {
      int ret = riscv_link_to(thread_data, &write_p, target_tpc);
      assert(ret == 0);
    }
  } else {
    uint16_t *branch = write_p;
    write_p += 2;
    enum branch_condition cond = invert_cond(bb_meta->branch_condition);
    if (!target_in_cc) {
      target_tpc = fallthrough_tpc;
      cond = invert_cond(cond);
      fallthrough_in_cc = 0;
    }
    int ret = riscv_link_to(thread_data, &write_p, target_tpc);
    assert(ret == 0);
    ret = riscv_branch_helper(&branch, (uintptr_t)write_p, bb_meta->rs1, bb_meta->rs2, cond);
    assert(ret == 0);

    if (fallthrough_in_cc) {
      int ret = riscv_link_to(thread_data, &write_p, fallthrough_tpc);
      assert(ret == 0);
    }
  }
  __clear_cache((void *)bb_meta->exit_branch_addr, (void *)write_p);
}

void dispatcher_riscv(dbm_thread *thread_data, uint32_t source_index, branch_type exit_type,
                      uintptr_t target, uintptr_t block_address) {
  switch (exit_type) {
#ifdef DBM_LINK_COND_IMM
    case branch_riscv:
      riscv_link_branch(thread_data, source_index, target);
      break;
#endif
#ifdef DBM_LINK_UNCOND_IMM
    case jal_riscv: {
      dbm_code_cache_meta *bb_meta = &thread_data->code_cache_meta[source_index];
      uint16_t *branch_addr = bb_meta->exit_branch_addr;
      int ret = riscv_link_to(thread_data, &branch_addr, block_address);
      assert(ret == 0);
      __clear_cache(bb_meta->exit_branch_addr, branch_addr);
      break;
    }
#endif
  }
}
