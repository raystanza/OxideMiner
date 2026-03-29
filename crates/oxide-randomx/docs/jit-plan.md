# RandomX JIT v1 Plan

This document captures the staged, correctness-first JIT scope for RandomX VM program execution
(`docs/randomx-refs/specs.md` §4.6 + §5). The interpreter remains the reference for all semantics.

## Scope and Strategy

- Compile only the VM program execution loop (program body).
- Conservative register strategy: integer and FP registers remain in `VmJitContext` memory; each
  instruction loads, operates, and stores back (auditable and deterministic).
- Helper calls are limited to iteration boundaries and light-mode cache item generation; float
  ops are inlined in the JIT body.

## Supported Platforms

- x86_64 Windows / Linux / macOS are supported in v1.
- Other architectures or OSes fall back to the interpreter automatically.

## ABI and Entry Point

- JIT entrypoint signature: `unsafe extern "C" fn(ctx: *mut VmJitContext)`.
- x86_64 calling conventions:
  - Windows x64: `ctx` in RCX, 16-byte stack alignment.
  - System V: `ctx` in RDI, 16-byte stack alignment.
- Callee-saved registers are preserved according to the platform ABI.

## CFROUND Plan

- CFROUND updates `fprc` based on `(src ror imm32) & 3` (see `docs/randomx-refs/specs.md` §5.4.1).
- MXCSR rounding control is updated inline on CFROUND; the saved MXCSR is restored before
  returning to Rust.

## CBRANCH Plan

- JIT tracks the “last modified” instruction index for each integer register, mirroring the
  interpreter bookkeeping (`docs/randomx-refs/specs.md` §5.4.2).
- CBRANCH uses the tracked state to compute jump targets deterministically.

## Caching Plan

- Each VM instance maintains a bounded FIFO cache of compiled programs.
- Cache keys include the 128-byte program configuration region, the program words, and any
  flags that alter code generation.
- Eviction frees executable memory promptly; no RWX mappings are kept.
