# Xtrace

Xtrace uses an online capture/offline decode pipeline by default. The runtime
records fixed-size events into a per-thread buffer, compresses each full block
with zstd, and writes the block under one output-lock acquisition. Instruction
formatting and disassembly run only in `xtrace_decode`.

## Build and run

```sh
make xtrace
MAMBO_XTRACE_FILE=workload.xtr ./mambo_xtrace ./workload
./xtrace_decode workload.xtr pinatrace.out
```

`make xtrace` builds both `mambo_xtrace` and `xtrace_decode`. The decoder must
be configured for the trace's ISA because it reuses MAMBO's
architecture-specific instruction decoder.

To decode a 64-bit trace on a different architecture, select the trace ISA
explicitly. For example, on an x86-64 server decoding an RV64 trace:

```sh
sudo apt install build-essential ruby libelf-dev libzstd-dev
make xtrace-decode XTRACE_ARCH=riscv64
./xtrace_decode workload.xtr pinatrace.out
```

Use `XTRACE_ARCH=aarch64` for an AArch64 trace. The resulting executable is
native to the build server; `XTRACE_ARCH` selects the instruction format it
decodes, not the architecture on which it runs. Use the same MAMBO source
revision that produced the trace so the recorded instruction enums match.

ARM32 traces additionally require a 32-bit decoder because the current format
checks the capture and decoder pointer sizes. On an x86-64 server this requires
a 32-bit toolchain and libraries, normally supplied through `CFLAGS=-m32` and
the distribution's multilib packages.

Binary capture writes `xtrace.bin` by default. The decoder writes text to
stdout when its second argument is omitted:

```sh
./xtrace_decode xtrace.bin > pinatrace.out
```

Use `MAMBO_XTRACE_FILE=-` to stream binary capture on stdout. Diagnostics and
the final compression summary are written to stderr.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `MAMBO_XTRACE_FILE` | `xtrace.bin` | Binary capture path; `-` means stdout |
| `MAMBO_XTRACE_FORMAT` | `binary` | Set to `text` for the legacy online formatter |
| `MAMBO_XTRACE_COMPRESSION_LEVEL` | `1` | Zstd compression level used per block |
| `MAMBO_XTRACE_TIMESTAMPS` | `clock` | Sampled `clock`, or `none` to disable timing |
| `MAMBO_XTRACE_CPU_HZ` | `1600000000` | CPU frequency used to convert sampled nanoseconds to cycles |
| `MAMBO_XTRACE_RING` | `3` | Ring value emitted by the text decoder |
| `MAMBO_XTRACE_BASE` | first PC | Override the PC printed by the ring header |
| `MAMBO_XTRACE_FUNCTIONS` | unset | Comma-separated ELF function names to capture |
| `MAMBO_XTRACE_FUNCTION_FILE` | unset | File containing function names, one per line |

## Selective function capture

To avoid the runtime cost and output volume of a whole-program trace, xtrace
can instrument only the functions identified as hot by perf:

```sh
MAMBO_XTRACE_FUNCTIONS=hot_function,other_hot_function \
  MAMBO_XTRACE_FILE=hot.xtr ./mambo_xtrace ./workload
```

For a generated list, put one ELF symbol name on each line. Blank lines and
lines starting with `#` are ignored; comma-separated names are also accepted
on a line:

```sh
MAMBO_XTRACE_FUNCTION_FILE=perf-hot-functions.txt \
  MAMBO_XTRACE_FILE=hot.xtr ./mambo_xtrace ./workload
```

The filter is applied while MAMBO translates each basic block. Blocks outside
the selected function bodies receive no xtrace instrumentation, rather than a
runtime check, so their execution does not pay the per-instruction tracing
cost. Calls made by a selected function are not traced unless the callee is
also selected. Function names must match the ELF symbol table exactly; use
mangled names for C++, and retain symbols in the binaries being measured.
Xtrace reports every configured name that did not match translated executable
code, either because its symbol was unavailable or the function was not run.

If both filter variables are set their names are combined. If neither is set,
xtrace retains whole-program capture behavior.

Direct `rdcycle` access is not used because Debian may disable the userspace
counter and raise `SIGILL`. The default `clock` mode samples
`CLOCK_MONOTONIC_RAW` once per 256 instructions and converts nanoseconds to
cycles during decoding using the configured 1.6 GHz frequency. Override the
frequency when necessary:

```sh
MAMBO_XTRACE_TIMESTAMPS=clock MAMBO_XTRACE_CPU_HZ=1600000000 \
  ./mambo_xtrace ./workload
```

Keep the CPU at that frequency while collecting. Set
`MAMBO_XTRACE_TIMESTAMPS=none` to emit `@0`, remove timing overhead, and prevent
`ptr_chase_analyzer` from reporting IPC when timing is not required.

`ptr_chase_analyzer` currently labels its seconds conversion as 3.29 GHz. On an
RV64 target with another frequency, use the cycle-window IPC value and ignore
that hard-coded seconds annotation.

The compatibility mode retains the old behavior and default filename:

```sh
MAMBO_XTRACE_FORMAT=text MAMBO_XTRACE_FILE=pinatrace.out \
  ./mambo_xtrace ./workload
```

## Operational notes

Each event is 32 bytes before compression and blocks contain at most 32,768
events. A crash can therefore leave the current block of each live thread
unwritten; all completed blocks remain independently decodable. The decoder
rejects truncated, cross-endian, wrong-version, and wrong-architecture input
instead of producing partial-looking output.

Blocks from different threads appear in flush order. Per-thread event order and
instruction-to-memory-access association are preserved, but binary mode does
not reconstruct a total instruction order across threads. Enable clock
timestamps when cross-thread timing is needed by a downstream analysis.

During decoding, xtrace inserts a `ring N, pc -> TARGET` line whenever the next
instruction PC differs from `previous PC + previous instruction length`. This
reconstructs taken branches, calls, returns, and loop back-edges offline without
adding a control-flow check to the online capture path.

Compression happens once per block, outside the per-event formatting path.
Actual size reduction depends on control-flow and address locality; the runtime
prints raw bytes, stored bytes, and the achieved ratio when capture finishes.
