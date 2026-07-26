/*
 * Populate more than 1 MiB of MAMBO basic-block cache entries, then execute a
 * direct jump from the newest entry to the oldest. A debug build of MAMBO with
 * DBM_JUMP_TRAMPOLINE_DEBUG reports that this link used jump trampolines.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#ifndef __riscv
#error This workload generates and executes RISC-V instructions
#endif

#define DEFAULT_FUNCTION_COUNT 10000
#define MAX_FUNCTION_COUNT 14000
#define RISCV_RET 0x00008067u

typedef void (*generated_function)(void);

static uint32_t encode_jal(int32_t offset) {
  if ((offset & 1) || offset < -(1 << 20) || offset >= (1 << 20)) {
    fprintf(stderr, "JAL offset is out of range: %d\n", offset);
    exit(EXIT_FAILURE);
  }

  return (((uint32_t)offset >> 20) & 0x1) << 31 |
         (((uint32_t)offset >> 1) & 0x3ff) << 21 |
         (((uint32_t)offset >> 11) & 0x1) << 20 |
         (((uint32_t)offset >> 12) & 0xff) << 12 |
         0x6f;
}

int main(int argc, char **argv) {
  int function_count = DEFAULT_FUNCTION_COUNT;
  if (argc == 2) {
    function_count = atoi(argv[1]);
  }
  if (function_count < 2 || function_count > MAX_FUNCTION_COUNT) {
    fprintf(stderr, "function count must be between 2 and %d\n",
            MAX_FUNCTION_COUNT);
    return EXIT_FAILURE;
  }

  size_t code_size = function_count * sizeof(uint32_t);
  uint32_t *code = mmap(NULL, code_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (code == MAP_FAILED) {
    perror("mmap");
    return EXIT_FAILURE;
  }

  for (int i = 0; i < function_count; i++) {
    code[i] = RISCV_RET;
  }
  code[function_count - 1] = encode_jal(-(function_count - 1) * 4);

  if (mprotect(code, code_size, PROT_READ | PROT_EXEC) != 0) {
    perror("mprotect");
    return EXIT_FAILURE;
  }
  __builtin___clear_cache((char *)code, (char *)code + code_size);

  ((generated_function)&code[0])();
  for (int i = 1; i < function_count - 1; i++) {
    ((generated_function)&code[i])();
  }

  for (int i = 0; i < 100; i++) {
    ((generated_function)&code[function_count - 1])();
  }

  puts("riscv jump trampoline workload passed");
  return EXIT_SUCCESS;
}
