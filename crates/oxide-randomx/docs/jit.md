# JIT Backend Notes

This document describes the baseline x86_64 JIT used by `oxide-randomx` when the `jit` feature is enabled. The JIT targets the RandomX VM program execution loop (docs/randomx-refs/specs.md §4.6 and §5) and is correctness-first.

## Calling convention

- Entry point: `unsafe extern "C" fn(ctx: *mut VmJitContext)`
- The JIT uses the platform ABI (SysV on Linux/macOS, Windows x64 on Windows).
- `r15` is reserved to hold the `VmJitContext` pointer inside the JIT body.
- Stack alignment and Windows shadow space are maintained for all helper calls.

## Context layout

`VmJitContext` is `#[repr(C)]` and provides everything needed to execute a program:

- `r`, `f`, `e`, `a`: pointers to integer and floating-point register files
- `scratchpad`: pointer to the scratchpad base
- `mask_l1`, `mask_l2`, `mask_l3`: scratchpad masks (docs/randomx-refs/specs.md §4.2)
- `e_mask_low`, `e_mask_high`: E register masks (docs/randomx-refs/specs.md §5.3)
- `fprc`: current rounding mode (docs/randomx-refs/specs.md §5.4.1)
- `jump_bits`, `jump_offset`: CBRANCH parameters (docs/randomx-refs/specs.md §5.4.2)
- `last_modified`: bookkeeping for CBRANCH targets
- `ip`: next instruction pointer

Offsets are computed once at compile time and embedded into the generated code.

## Codegen strategy

The JIT emits a simple dispatcher plus a linear block per instruction. Integer, floating-point, and CBRANCH instructions are emitted inline using the same semantics as the interpreter (including CFROUND-driven MXCSR updates). Conservative JIT caches f/e/a/scratchpad base pointers in callee-saved registers and relies on Rust helpers only for prepare/finish iteration boundaries.

The fast-regs path maps the integer register file into host registers and keeps it live across the program loop. Prepare/finish are inlined for dataset-backed (fast) mode to avoid full ctx sync; light-mode finish uses a small helper to compute cache item words without syncing the full
register file.

## CFROUND and CBRANCH

- CFROUND updates `fprc` in the context and updates MXCSR inline (docs/randomx-refs/specs.md §5.4.1).
- CBRANCH uses `last_modified` exactly as in the interpreter and computes the next `ip` based on `jump_bits` and `jump_offset` (docs/randomx-refs/specs.md §5.4.2).

## Executable memory (W^X)

The JIT uses a dedicated `ExecutableBuffer`:

- Allocate RW pages, write machine code, then flip to RX (never RWX).
- Windows: `VirtualAlloc` + `VirtualProtect`
- Unix: `mmap` + `mprotect`

## Cache strategy

Each VM owns a small FIFO cache of compiled programs (default 256 entries), keyed by the program byte stream. This avoids recompiling identical programs while keeping memory bounded.

## Limitations

- Only x86_64 is supported today.
- Helper calls remain at iteration boundaries in conservative JIT; light-mode fast-regs finish uses a cache-item helper, and float helpers are retained for tests.
