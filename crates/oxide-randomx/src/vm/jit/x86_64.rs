//! x86_64 JIT code generation.

use super::super::{reciprocal_u64, Instruction, InstructionKind, VmJitContext};
use super::executable::ExecutableBuffer;
#[cfg(feature = "jit-fastregs")]
use super::helpers::jit_compute_cache_item_words_fastregs;
#[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
use super::helpers::jit_monotonic_ns;
use super::helpers::{jit_finish_iteration, jit_prepare_iteration};
#[cfg(feature = "bench-instrument")]
use super::InstructionMix;
use super::{JitFn, JitProgram};

use crate::errors::{RandomXError, Result};
use core::mem::MaybeUninit;
use core::ptr::addr_of;
use dynasmrt::x64::Assembler;
#[cfg(feature = "jit-fastregs")]
use dynasmrt::x64::Rq;
use dynasmrt::{dynasm, DynamicLabel, DynasmApi, DynasmLabelApi};

struct JitOffsets {
    r: i32,
    f: i32,
    e: i32,
    a: i32,
    scratchpad: i32,
    mask_l1: i32,
    mask_l2: i32,
    mask_l3: i32,
    e_mask_low: i32,
    e_mask_high: i32,
    fprc: i32,
    saved_mxcsr: i32,
    jump_bits: i32,
    jump_offset: i32,
    last_modified: i32,
    ip: i32,
    program_iters: i32,
    #[cfg(feature = "jit-fastregs")]
    sp_addr0: i32,
    #[cfg(feature = "jit-fastregs")]
    sp_addr1: i32,
    #[cfg(feature = "jit-fastregs")]
    mx_ptr: i32,
    #[cfg(feature = "jit-fastregs")]
    ma_ptr: i32,
    #[cfg(feature = "jit-fastregs")]
    dataset_ptr: i32,
    #[cfg(feature = "jit-fastregs")]
    dataset_items: i32,
    #[cfg(feature = "jit-fastregs")]
    dataset_base: i32,
    #[cfg(feature = "jit-fastregs")]
    dataset_offset: i32,
    #[cfg(feature = "jit-fastregs")]
    prefetch: i32,
    prefetch_scratchpad: i32,
    #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
    jit_fastregs_spill_count: i32,
    #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
    jit_fastregs_reload_count: i32,
    #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
    jit_fastregs_sync_to_ctx_count: i32,
    #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
    jit_fastregs_sync_from_ctx_count: i32,
    #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
    #[allow(dead_code)]
    jit_fastregs_call_boundary_float_nomem: i32,
    #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
    #[allow(dead_code)]
    jit_fastregs_call_boundary_float_mem: i32,
    #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
    #[allow(dead_code)]
    jit_fastregs_call_boundary_prepare_finish: i32,
    #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
    jit_fastregs_preserve_spill_count: i32,
    #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
    jit_fastregs_preserve_reload_count: i32,
    #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
    jit_fastregs_prepare_ns: i32,
    #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
    jit_fastregs_finish_ns: i32,
    #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
    jit_fastregs_stage_start_ns: i32,
}

impl JitOffsets {
    fn new() -> Self {
        let base = MaybeUninit::<VmJitContext>::uninit();
        let base_ptr = base.as_ptr();
        unsafe {
            Self {
                r: (addr_of!((*base_ptr).r) as usize - base_ptr as usize) as i32,
                f: (addr_of!((*base_ptr).f) as usize - base_ptr as usize) as i32,
                e: (addr_of!((*base_ptr).e) as usize - base_ptr as usize) as i32,
                a: (addr_of!((*base_ptr).a) as usize - base_ptr as usize) as i32,
                scratchpad: (addr_of!((*base_ptr).scratchpad) as usize - base_ptr as usize) as i32,
                mask_l1: (addr_of!((*base_ptr).mask_l1) as usize - base_ptr as usize) as i32,
                mask_l2: (addr_of!((*base_ptr).mask_l2) as usize - base_ptr as usize) as i32,
                mask_l3: (addr_of!((*base_ptr).mask_l3) as usize - base_ptr as usize) as i32,
                e_mask_low: (addr_of!((*base_ptr).e_mask_low) as usize - base_ptr as usize) as i32,
                e_mask_high: (addr_of!((*base_ptr).e_mask_high) as usize - base_ptr as usize)
                    as i32,
                fprc: (addr_of!((*base_ptr).fprc) as usize - base_ptr as usize) as i32,
                saved_mxcsr: (addr_of!((*base_ptr).saved_mxcsr) as usize - base_ptr as usize)
                    as i32,
                jump_bits: (addr_of!((*base_ptr).jump_bits) as usize - base_ptr as usize) as i32,
                jump_offset: (addr_of!((*base_ptr).jump_offset) as usize - base_ptr as usize)
                    as i32,
                last_modified: (addr_of!((*base_ptr).last_modified) as usize - base_ptr as usize)
                    as i32,
                ip: (addr_of!((*base_ptr).ip) as usize - base_ptr as usize) as i32,
                program_iters: (addr_of!((*base_ptr).program_iters) as usize - base_ptr as usize)
                    as i32,
                #[cfg(feature = "jit-fastregs")]
                sp_addr0: (addr_of!((*base_ptr).sp_addr0) as usize - base_ptr as usize) as i32,
                #[cfg(feature = "jit-fastregs")]
                sp_addr1: (addr_of!((*base_ptr).sp_addr1) as usize - base_ptr as usize) as i32,
                #[cfg(feature = "jit-fastregs")]
                mx_ptr: (addr_of!((*base_ptr).mx_ptr) as usize - base_ptr as usize) as i32,
                #[cfg(feature = "jit-fastregs")]
                ma_ptr: (addr_of!((*base_ptr).ma_ptr) as usize - base_ptr as usize) as i32,
                #[cfg(feature = "jit-fastregs")]
                dataset_ptr: (addr_of!((*base_ptr).dataset_ptr) as usize - base_ptr as usize)
                    as i32,
                #[cfg(feature = "jit-fastregs")]
                dataset_items: (addr_of!((*base_ptr).dataset_items) as usize - base_ptr as usize)
                    as i32,
                #[cfg(feature = "jit-fastregs")]
                dataset_base: (addr_of!((*base_ptr).dataset_base) as usize - base_ptr as usize)
                    as i32,
                #[cfg(feature = "jit-fastregs")]
                dataset_offset: (addr_of!((*base_ptr).dataset_offset) as usize - base_ptr as usize)
                    as i32,
                #[cfg(feature = "jit-fastregs")]
                prefetch: (addr_of!((*base_ptr).prefetch) as usize - base_ptr as usize) as i32,
                prefetch_scratchpad: (addr_of!((*base_ptr).prefetch_scratchpad) as usize
                    - base_ptr as usize) as i32,
                #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
                jit_fastregs_spill_count: (addr_of!((*base_ptr).jit_fastregs_spill_count) as usize
                    - base_ptr as usize) as i32,
                #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
                jit_fastregs_reload_count: (addr_of!((*base_ptr).jit_fastregs_reload_count)
                    as usize
                    - base_ptr as usize) as i32,
                #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
                jit_fastregs_sync_to_ctx_count: (addr_of!(
                    (*base_ptr).jit_fastregs_sync_to_ctx_count
                ) as usize
                    - base_ptr as usize) as i32,
                #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
                jit_fastregs_sync_from_ctx_count: (addr_of!(
                    (*base_ptr).jit_fastregs_sync_from_ctx_count
                ) as usize
                    - base_ptr as usize) as i32,
                #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
                jit_fastregs_call_boundary_float_nomem: (addr_of!(
                    (*base_ptr).jit_fastregs_call_boundary_float_nomem
                ) as usize
                    - base_ptr as usize)
                    as i32,
                #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
                jit_fastregs_call_boundary_float_mem: (addr_of!(
                    (*base_ptr).jit_fastregs_call_boundary_float_mem
                ) as usize
                    - base_ptr as usize)
                    as i32,
                #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
                jit_fastregs_call_boundary_prepare_finish: (addr_of!(
                    (*base_ptr).jit_fastregs_call_boundary_prepare_finish
                ) as usize
                    - base_ptr as usize)
                    as i32,
                #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
                jit_fastregs_preserve_spill_count: (addr_of!(
                    (*base_ptr).jit_fastregs_preserve_spill_count
                ) as usize
                    - base_ptr as usize) as i32,
                #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
                jit_fastregs_preserve_reload_count: (addr_of!(
                    (*base_ptr).jit_fastregs_preserve_reload_count
                ) as usize
                    - base_ptr as usize) as i32,
                #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
                jit_fastregs_prepare_ns: (addr_of!((*base_ptr).jit_fastregs_prepare_ns) as usize
                    - base_ptr as usize) as i32,
                #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
                jit_fastregs_finish_ns: (addr_of!((*base_ptr).jit_fastregs_finish_ns) as usize
                    - base_ptr as usize) as i32,
                #[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
                jit_fastregs_stage_start_ns: (addr_of!((*base_ptr).jit_fastregs_stage_start_ns)
                    as usize
                    - base_ptr as usize) as i32,
            }
        }
    }
}

#[cfg(all(feature = "jit-fastregs", target_os = "windows"))]
const FAST_REGS: [Rq; 8] = [
    Rq::RBX,
    Rq::RBP,
    Rq::RSI,
    Rq::RDI,
    Rq::R12,
    Rq::R13,
    Rq::R14,
    Rq::R10,
];

#[cfg(all(feature = "jit-fastregs", not(target_os = "windows")))]
const FAST_REGS: [Rq; 8] = [
    Rq::R12,
    Rq::R13,
    Rq::R14,
    Rq::RBX,
    Rq::RBP,
    Rq::R8,
    Rq::R9,
    Rq::R10,
];

#[cfg(all(feature = "jit-fastregs", target_os = "windows"))]
const FAST_REGS_VOLATILE: [usize; 1] = [7];

#[cfg(all(feature = "jit-fastregs", target_os = "windows"))]
const FAST_REGS_SPILL_BYTES: i32 = (FAST_REGS_VOLATILE.len() as i32) * 8;

#[cfg(all(feature = "jit-fastregs", target_os = "windows"))]
const FAST_REGS_STACK_BUFFER_BYTES: i32 = 0x40;

#[cfg(all(feature = "jit-fastregs", target_os = "windows"))]
const FAST_REGS_STACK_RESERVE: i32 = 0x20 + FAST_REGS_SPILL_BYTES + FAST_REGS_STACK_BUFFER_BYTES;

#[cfg(all(feature = "jit-fastregs", target_os = "windows"))]
const FAST_REGS_STACK_BUFFER_BASE: i32 = 0x20 + FAST_REGS_SPILL_BYTES;

#[cfg(all(feature = "jit-fastregs", target_os = "windows"))]
const FAST_REGS_SPILL_BASE: i32 = 0x20;

#[cfg(all(feature = "jit-fastregs", not(target_os = "windows")))]
const FAST_REGS_VOLATILE: [usize; 3] = [5, 6, 7];

#[cfg(all(feature = "jit-fastregs", not(target_os = "windows")))]
const FAST_REGS_SPILL_BYTES: i32 = (FAST_REGS_VOLATILE.len() as i32) * 8;

#[cfg(all(feature = "jit-fastregs", not(target_os = "windows")))]
const FAST_REGS_STACK_SCRATCH: i32 = 0x10;

#[cfg(all(feature = "jit-fastregs", not(target_os = "windows")))]
const FAST_REGS_STACK_BUFFER_BYTES: i32 = 0x40;

#[cfg(all(feature = "jit-fastregs", not(target_os = "windows")))]
const FAST_REGS_STACK_RESERVE: i32 =
    FAST_REGS_STACK_SCRATCH + FAST_REGS_SPILL_BYTES + FAST_REGS_STACK_BUFFER_BYTES;

#[cfg(all(feature = "jit-fastregs", not(target_os = "windows")))]
const FAST_REGS_STACK_BUFFER_BASE: i32 = FAST_REGS_STACK_SCRATCH + FAST_REGS_SPILL_BYTES;

#[cfg(all(feature = "jit-fastregs", not(target_os = "windows")))]
const FAST_REGS_SPILL_BASE: i32 = FAST_REGS_STACK_SCRATCH;

#[cfg(feature = "jit-fastregs")]
fn reg_for(idx: usize) -> Rq {
    FAST_REGS[idx]
}

#[cfg(feature = "jit-fastregs")]
const MASK_L3_64: i32 = -64;

/// Compile a RandomX program into a JIT program.
pub fn compile(
    program_bytes: &[u8],
    program: &[Instruction],
    fast_regs: bool,
) -> Result<JitProgram> {
    #[cfg(not(feature = "jit-fastregs"))]
    let _ = program_bytes;
    if fast_regs {
        #[cfg(feature = "jit-fastregs")]
        {
            let read_regs = read_regs_from_program_bytes(program_bytes)?;
            if let Ok(program) = compile_fast(program, read_regs) {
                return Ok(program);
            }
        }
    }
    compile_conservative(program)
}

#[cfg(feature = "jit-fastregs")]
fn read_regs_from_program_bytes(program_bytes: &[u8]) -> Result<[usize; 4]> {
    let selector_chunk = program_bytes
        .chunks_exact(8)
        .nth(12)
        .ok_or(RandomXError::InvalidArgument("jit program bytes too short"))?;
    let selector = u64::from_le_bytes(
        selector_chunk
            .try_into()
            .expect("jit selector word should be 8 bytes"),
    ) as u8;
    Ok([
        if selector & 0x1 == 0 { 0 } else { 1 },
        if selector & 0x2 == 0 { 2 } else { 3 },
        if selector & 0x4 == 0 { 4 } else { 5 },
        if selector & 0x8 == 0 { 6 } else { 7 },
    ])
}

fn compile_conservative(program: &[Instruction]) -> Result<JitProgram> {
    if program.is_empty() {
        return Err(RandomXError::InvalidArgument("jit program is empty"));
    }
    let offsets = JitOffsets::new();
    let instructions = program.to_vec();
    let mut ops = Assembler::new().map_err(|_| RandomXError::AllocationFailed("jit assembler"))?;

    dynasm!(ops
        ; .arch x64
    );

    let dispatch = ops.new_dynamic_label();
    let jump_table = ops.new_dynamic_label();
    let exit = ops.new_dynamic_label();
    let loop_start = ops.new_dynamic_label();
    let done = ops.new_dynamic_label();
    let fscal_mask = ops.new_dynamic_label();
    let labels: Vec<_> = (0..instructions.len())
        .map(|_| ops.new_dynamic_label())
        .collect();

    dynasm!(ops
        ; push r15
        ; push r14
        ; push r13
        ; push r12
        ; push rbx
        ; push rbp
    );
    #[cfg(target_os = "windows")]
    dynasm!(ops
        ; mov r15, rcx
        ; mov r14, QWORD [r15 + offsets.r]
        ; mov rbx, QWORD [r15 + offsets.f]
        ; mov rbp, QWORD [r15 + offsets.e]
        ; mov r12, QWORD [r15 + offsets.a]
        ; mov r13, QWORD [r15 + offsets.scratchpad]
        ; sub rsp, 0x28
    );
    #[cfg(not(target_os = "windows"))]
    dynasm!(ops
        ; mov r15, rdi
        ; mov r14, QWORD [r15 + offsets.r]
        ; mov rbx, QWORD [r15 + offsets.f]
        ; mov rbp, QWORD [r15 + offsets.e]
        ; mov r12, QWORD [r15 + offsets.a]
        ; mov r13, QWORD [r15 + offsets.scratchpad]
        ; sub rsp, 0x8
    );
    dynasm!(ops
        ; stmxcsr DWORD [r15 + offsets.saved_mxcsr]
    );
    emit_set_mxcsr_from_fprc(&mut ops, &offsets);
    dynasm!(ops
        ; mov eax, DWORD [r15 + offsets.program_iters]
        ; test eax, eax
        ; jnz =>loop_start
        ; mov DWORD [r15 + offsets.ip], 0
        ; jmp =>dispatch
        ; =>loop_start
    );
    emit_call_prepare(&mut ops);
    dynasm!(ops
        ; jmp =>dispatch
    );

    dynasm!(ops
        ; =>dispatch
        ; mov eax, DWORD [r15 + offsets.ip]
        ; cmp eax, DWORD instructions.len() as i32
        ; ja =>exit
        ; lea r11, [=>jump_table]
        ; jmp QWORD [r11 + rax*8]
    );

    for (idx, instr) in instructions.iter().enumerate() {
        dynasm!(ops
            ; =>labels[idx]
        );
        match instr.kind {
            InstructionKind::IAddRs => {
                emit_iadd_rs(&mut ops, &offsets, instr, idx);
            }
            InstructionKind::IAddM => {
                emit_mem_read_op(&mut ops, &offsets, instr, idx, MemOp::Add);
            }
            InstructionKind::ISubR => {
                emit_int_binop(&mut ops, &offsets, instr, idx, IntOp::Sub);
            }
            InstructionKind::ISubM => {
                emit_mem_read_op(&mut ops, &offsets, instr, idx, MemOp::Sub);
            }
            InstructionKind::IMulR => {
                emit_int_binop(&mut ops, &offsets, instr, idx, IntOp::Mul);
            }
            InstructionKind::IMulM => {
                emit_mem_read_op(&mut ops, &offsets, instr, idx, MemOp::Mul);
            }
            InstructionKind::IMulH_R => {
                emit_mulh_reg(&mut ops, &offsets, instr, idx, false);
            }
            InstructionKind::IMulH_M => {
                emit_mulh_mem(&mut ops, &offsets, instr, idx, false);
            }
            InstructionKind::ISMulH_R => {
                emit_mulh_reg(&mut ops, &offsets, instr, idx, true);
            }
            InstructionKind::ISMulH_M => {
                emit_mulh_mem(&mut ops, &offsets, instr, idx, true);
            }
            InstructionKind::IMulRcp => {
                let dst = instr.dst;
                let imm = instr.imm as u64;
                if imm != 0 && !imm.is_power_of_two() {
                    let rcp = reciprocal_u64(imm);
                    let r_dst = dst as i32 * 8;
                    let last = offsets.last_modified + (dst as i32 * 4);
                    dynasm!(ops
                        ; mov rax, QWORD [r14 + r_dst]
                        ; mov rdx, QWORD rcp as i64
                        ; imul rax, rdx
                        ; mov QWORD [r14 + r_dst], rax
                        ; mov DWORD [r15 + last], DWORD idx as i32
                    );
                }
            }
            InstructionKind::INegR => {
                let dst = instr.dst;
                let r_dst = dst as i32 * 8;
                let last = offsets.last_modified + (dst as i32 * 4);
                dynasm!(ops
                    ; mov rax, QWORD [r14 + r_dst]
                    ; neg rax
                    ; mov QWORD [r14 + r_dst], rax
                    ; mov DWORD [r15 + last], DWORD idx as i32
                );
            }
            InstructionKind::IXorR => {
                emit_int_binop(&mut ops, &offsets, instr, idx, IntOp::Xor);
            }
            InstructionKind::IXorM => {
                emit_mem_read_op(&mut ops, &offsets, instr, idx, MemOp::Xor);
            }
            InstructionKind::IRorR => {
                emit_rot(&mut ops, &offsets, instr, idx, true);
            }
            InstructionKind::IRolR => {
                emit_rot(&mut ops, &offsets, instr, idx, false);
            }
            InstructionKind::ISwapR => {
                let dst = instr.dst;
                let src = instr.src;
                if dst != src {
                    let r_dst = dst as i32 * 8;
                    let r_src = src as i32 * 8;
                    let last_dst = offsets.last_modified + (dst as i32 * 4);
                    let last_src = offsets.last_modified + (src as i32 * 4);
                    dynasm!(ops
                        ; mov rax, QWORD [r14 + r_dst]
                        ; mov rdx, QWORD [r14 + r_src]
                        ; mov QWORD [r14 + r_dst], rdx
                        ; mov QWORD [r14 + r_src], rax
                        ; mov DWORD [r15 + last_dst], DWORD idx as i32
                        ; mov DWORD [r15 + last_src], DWORD idx as i32
                    );
                }
            }
            InstructionKind::FSwapR => {
                let idx = instr.dst;
                if idx < 4 {
                    emit_float_swap_inline_cached(&mut ops, idx, false);
                } else {
                    emit_float_swap_inline_cached(&mut ops, idx - 4, true);
                }
            }
            InstructionKind::FAddR => {
                emit_float_add_sub_r_inline_cached(&mut ops, instr, true);
            }
            InstructionKind::FSubR => {
                emit_float_add_sub_r_inline_cached(&mut ops, instr, false);
            }
            InstructionKind::FScalR => {
                emit_float_scal_inline_cached(&mut ops, instr, fscal_mask);
            }
            InstructionKind::FMulR => {
                emit_float_mul_r_inline_cached(&mut ops, instr);
            }
            InstructionKind::FSqrtR => {
                emit_float_sqrt_r_inline_cached(&mut ops, instr);
            }
            InstructionKind::FAddM => {
                emit_float_add_sub_m_inline_cached(&mut ops, &offsets, instr, true);
            }
            InstructionKind::FSubM => {
                emit_float_add_sub_m_inline_cached(&mut ops, &offsets, instr, false);
            }
            InstructionKind::FDivM => {
                emit_float_div_m_inline_cached(&mut ops, &offsets, instr);
            }
            InstructionKind::CFround => {
                // CFROUND updates fprc and MXCSR (docs/randomx-refs/specs.md 5.4.1).
                let src = instr.src;
                let r_src = src as i32 * 8;
                let rot = (instr.imm & 63) as u8;
                dynasm!(ops
                    ; mov rax, QWORD [r14 + r_src]
                );
                if rot != 0 {
                    dynasm!(ops
                        ; ror rax, BYTE rot as i8
                    );
                }
                dynasm!(ops
                    ; and eax, 3
                    ; mov DWORD [r15 + offsets.fprc], eax
                    ; stmxcsr DWORD [rsp]
                    ; mov edx, DWORD [rsp]
                    ; and edx, DWORD 0xFFFF9FFFu32 as i32
                    ; shl eax, 13
                    ; or edx, eax
                    ; mov DWORD [rsp], edx
                    ; ldmxcsr DWORD [rsp]
                );
            }
            InstructionKind::CBranch => {
                emit_cbranch_inline(&mut ops, &offsets, instr, idx, jump_table);
            }
            InstructionKind::IStore => {
                emit_store(&mut ops, &offsets, instr);
            }
        }
    }

    dynasm!(ops
        ; =>exit
        ; mov eax, DWORD [r15 + offsets.program_iters]
        ; test eax, eax
        ; je =>done
    );
    emit_call_finish(&mut ops);
    dynasm!(ops
        ; dec DWORD [r15 + offsets.program_iters]
        ; jnz =>loop_start
        ; =>done
        ; ldmxcsr DWORD [r15 + offsets.saved_mxcsr]
    );
    #[cfg(target_os = "windows")]
    dynasm!(ops
        ; add rsp, 0x28
    );
    #[cfg(not(target_os = "windows"))]
    dynasm!(ops
        ; add rsp, 0x8
    );
    dynasm!(ops
        ; pop rbp
        ; pop rbx
        ; pop r12
        ; pop r13
        ; pop r14
        ; pop r15
        ; ret
    );

    dynasm!(ops
        ; .align 16
        ; =>fscal_mask
        ; .u64 0x80F0_0000_0000_0000u64
        ; .u64 0x80F0_0000_0000_0000u64
    );

    dynasm!(ops
        ; .align 8
        ; =>jump_table
    );
    for _ in 0..=labels.len() {
        dynasm!(ops
            ; .u64 0
        );
    }

    let jump_table_offset = ops
        .labels()
        .resolve_dynamic(jump_table)
        .map_err(|_| RandomXError::AllocationFailed("jit label"))?
        .0;
    let mut jump_targets = Vec::with_capacity(labels.len() + 1);
    for label in labels.iter() {
        let offset = ops
            .labels()
            .resolve_dynamic(*label)
            .map_err(|_| RandomXError::AllocationFailed("jit label"))?
            .0;
        jump_targets.push(offset);
    }
    let exit_offset = ops
        .labels()
        .resolve_dynamic(exit)
        .map_err(|_| RandomXError::AllocationFailed("jit label"))?
        .0;
    jump_targets.push(exit_offset);

    let exec = ops
        .finalize()
        .map_err(|_| RandomXError::AllocationFailed("jit finalize"))?;
    let mut exec_bytes = exec.to_vec();
    let mut buffer = ExecutableBuffer::new(exec_bytes.len())?;
    let base_ptr = unsafe { buffer.as_fn_ptr::<*const u8>() } as usize;
    for (idx, target) in jump_targets.iter().enumerate() {
        let addr = base_ptr.wrapping_add(*target);
        let offset = jump_table_offset + (idx * 8);
        exec_bytes[offset..offset + 8].copy_from_slice(&addr.to_le_bytes());
    }
    buffer.write(&exec_bytes)?;
    buffer.finalize_rx()?;
    let entry_ptr = unsafe { buffer.as_fn_ptr::<JitFn>() };
    Ok(JitProgram {
        _buffer: buffer,
        entry: entry_ptr,
        _instructions: instructions,
        #[cfg(feature = "bench-instrument")]
        instr_mix: InstructionMix::default(),
    })
}

#[cfg(feature = "jit-fastregs")]
fn compile_fast(program: &[Instruction], read_regs: [usize; 4]) -> Result<JitProgram> {
    if program.is_empty() {
        return Err(RandomXError::InvalidArgument("jit program is empty"));
    }
    let offsets = JitOffsets::new();
    let instructions = program.to_vec();
    let mut ops = Assembler::new().map_err(|_| RandomXError::AllocationFailed("jit assembler"))?;

    dynasm!(ops
        ; .arch x64
    );

    let dispatch = ops.new_dynamic_label();
    let jump_table = ops.new_dynamic_label();
    let exit = ops.new_dynamic_label();
    let loop_start = ops.new_dynamic_label();
    let done = ops.new_dynamic_label();
    let done_program_only = ops.new_dynamic_label();
    let fscal_mask = ops.new_dynamic_label();
    let labels: Vec<_> = (0..instructions.len())
        .map(|_| ops.new_dynamic_label())
        .collect();

    dynasm!(ops
        ; push r15
        ; push r14
        ; push r13
        ; push r12
        ; push rbx
        ; push rbp
    );
    #[cfg(target_os = "windows")]
    // Win64: preserve nonvolatile regs used for fast-reg mapping (RSI/RDI).
    dynasm!(ops
        ; push rsi
        ; push rdi
    );
    #[cfg(target_os = "windows")]
    // Win64: reserve shadow space plus spill slots (stack stays 16-byte aligned for calls).
    dynasm!(ops
        ; mov r15, rcx
        ; sub rsp, FAST_REGS_STACK_RESERVE
    );
    #[cfg(not(target_os = "windows"))]
    dynasm!(ops
        ; mov r15, rdi
        ; sub rsp, FAST_REGS_STACK_RESERVE
    );

    emit_load_regs(&mut ops, &offsets);
    dynasm!(ops
        ; stmxcsr DWORD [r15 + offsets.saved_mxcsr]
    );
    emit_set_mxcsr_from_fprc(&mut ops, &offsets);
    dynasm!(ops
        ; mov eax, DWORD [r15 + offsets.program_iters]
        ; test eax, eax
        ; jnz =>loop_start
        ; mov DWORD [r15 + offsets.ip], 0
        ; jmp =>dispatch
        ; =>loop_start
    );
    emit_prepare_inline_fast(&mut ops, &offsets, read_regs);
    dynasm!(ops
        ; jmp =>dispatch
    );

    dynasm!(ops
        ; =>dispatch
        ; mov eax, DWORD [r15 + offsets.ip]
        ; cmp eax, DWORD instructions.len() as i32
        ; ja =>exit
        ; lea r11, [=>jump_table]
        ; jmp QWORD [r11 + rax*8]
    );

    for (idx, instr) in instructions.iter().enumerate() {
        dynasm!(ops
            ; =>labels[idx]
        );
        match instr.kind {
            InstructionKind::IAddRs => {
                emit_iadd_rs_fast(&mut ops, &offsets, instr, idx);
            }
            InstructionKind::IAddM => {
                emit_mem_read_op_fast(&mut ops, &offsets, instr, idx, MemOp::Add);
            }
            InstructionKind::ISubR => {
                emit_int_binop_fast(&mut ops, &offsets, instr, idx, IntOp::Sub);
            }
            InstructionKind::ISubM => {
                emit_mem_read_op_fast(&mut ops, &offsets, instr, idx, MemOp::Sub);
            }
            InstructionKind::IMulR => {
                emit_int_binop_fast(&mut ops, &offsets, instr, idx, IntOp::Mul);
            }
            InstructionKind::IMulM => {
                emit_mem_read_op_fast(&mut ops, &offsets, instr, idx, MemOp::Mul);
            }
            InstructionKind::IMulH_R => {
                emit_mulh_reg_fast(&mut ops, &offsets, instr, idx, false);
            }
            InstructionKind::IMulH_M => {
                emit_mulh_mem_fast(&mut ops, &offsets, instr, idx, false);
            }
            InstructionKind::ISMulH_R => {
                emit_mulh_reg_fast(&mut ops, &offsets, instr, idx, true);
            }
            InstructionKind::ISMulH_M => {
                emit_mulh_mem_fast(&mut ops, &offsets, instr, idx, true);
            }
            InstructionKind::IMulRcp => {
                let dst = instr.dst;
                let imm = instr.imm as u64;
                if imm != 0 && !imm.is_power_of_two() {
                    let rcp = reciprocal_u64(imm);
                    let dst_reg = reg_for(dst);
                    let last = offsets.last_modified + (dst as i32 * 4);
                    dynasm!(ops
                        ; mov rax, Rq(dst_reg)
                        ; mov rdx, QWORD rcp as i64
                        ; imul rax, rdx
                        ; mov Rq(dst_reg), rax
                        ; mov DWORD [r15 + last], DWORD idx as i32
                    );
                }
            }
            InstructionKind::INegR => {
                let dst = instr.dst;
                let dst_reg = reg_for(dst);
                let last = offsets.last_modified + (dst as i32 * 4);
                dynasm!(ops
                    ; neg Rq(dst_reg)
                    ; mov DWORD [r15 + last], DWORD idx as i32
                );
            }
            InstructionKind::IXorR => {
                emit_int_binop_fast(&mut ops, &offsets, instr, idx, IntOp::Xor);
            }
            InstructionKind::IXorM => {
                emit_mem_read_op_fast(&mut ops, &offsets, instr, idx, MemOp::Xor);
            }
            InstructionKind::IRorR => {
                emit_rot_fast(&mut ops, &offsets, instr, idx, true);
            }
            InstructionKind::IRolR => {
                emit_rot_fast(&mut ops, &offsets, instr, idx, false);
            }
            InstructionKind::ISwapR => {
                let dst = instr.dst;
                let src = instr.src;
                if dst != src {
                    let dst_reg = reg_for(dst);
                    let src_reg = reg_for(src);
                    let last_dst = offsets.last_modified + (dst as i32 * 4);
                    let last_src = offsets.last_modified + (src as i32 * 4);
                    dynasm!(ops
                        ; mov rax, Rq(dst_reg)
                        ; mov rdx, Rq(src_reg)
                        ; mov Rq(dst_reg), rdx
                        ; mov Rq(src_reg), rax
                        ; mov DWORD [r15 + last_dst], DWORD idx as i32
                        ; mov DWORD [r15 + last_src], DWORD idx as i32
                    );
                }
            }
            InstructionKind::FSwapR => {
                let idx = instr.dst;
                if idx < 4 {
                    emit_float_swap_inline(&mut ops, &offsets, idx, false);
                } else {
                    emit_float_swap_inline(&mut ops, &offsets, idx - 4, true);
                }
            }
            InstructionKind::FAddR => {
                emit_float_add_sub_r_inline(&mut ops, &offsets, instr, true);
            }
            InstructionKind::FSubR => {
                emit_float_add_sub_r_inline(&mut ops, &offsets, instr, false);
            }
            InstructionKind::FScalR => {
                emit_float_scal_inline(&mut ops, &offsets, instr, fscal_mask);
            }
            InstructionKind::FMulR => {
                emit_float_mul_r_inline(&mut ops, &offsets, instr);
            }
            InstructionKind::FSqrtR => {
                emit_float_sqrt_r_inline(&mut ops, &offsets, instr);
            }
            InstructionKind::FAddM => {
                emit_float_add_sub_m_inline_fast(&mut ops, &offsets, instr, true);
            }
            InstructionKind::FSubM => {
                emit_float_add_sub_m_inline_fast(&mut ops, &offsets, instr, false);
            }
            InstructionKind::FDivM => {
                emit_float_div_m_inline_fast(&mut ops, &offsets, instr);
            }
            InstructionKind::CFround => {
                // CFROUND updates fprc and MXCSR (docs/randomx-refs/specs.md 5.4.1).
                let src = instr.src;
                let src_reg = reg_for(src);
                let rot = (instr.imm & 63) as u8;
                dynasm!(ops
                    ; mov rax, Rq(src_reg)
                );
                if rot != 0 {
                    dynasm!(ops
                        ; ror rax, BYTE rot as i8
                    );
                }
                dynasm!(ops
                    ; and eax, 3
                    ; mov DWORD [r15 + offsets.fprc], eax
                    ; stmxcsr DWORD [rsp]
                    ; mov edx, DWORD [rsp]
                    ; and edx, DWORD 0xFFFF9FFFu32 as i32
                    ; shl eax, 13
                    ; or edx, eax
                    ; mov DWORD [rsp], edx
                    ; ldmxcsr DWORD [rsp]
                );
            }
            InstructionKind::CBranch => {
                emit_cbranch_inline_fast(&mut ops, &offsets, instr, idx, jump_table);
            }
            InstructionKind::IStore => {
                emit_store_fast(&mut ops, &offsets, instr);
            }
        }
    }

    dynasm!(ops
        ; =>exit
        ; mov eax, DWORD [r15 + offsets.program_iters]
        ; test eax, eax
        ; je =>done_program_only
    );
    emit_finish_inline_fast(&mut ops, &offsets, read_regs);
    dynasm!(ops
        ; dec DWORD [r15 + offsets.program_iters]
        ; jnz =>loop_start
        ; =>done_program_only
    );
    emit_store_regs(&mut ops, &offsets);
    dynasm!(ops
        ; =>done
        ; ldmxcsr DWORD [r15 + offsets.saved_mxcsr]
    );
    #[cfg(target_os = "windows")]
    dynasm!(ops
        ; add rsp, FAST_REGS_STACK_RESERVE
    );
    #[cfg(not(target_os = "windows"))]
    dynasm!(ops
        ; add rsp, FAST_REGS_STACK_RESERVE
    );
    #[cfg(target_os = "windows")]
    dynasm!(ops
        ; pop rdi
        ; pop rsi
    );
    dynasm!(ops
        ; pop rbp
        ; pop rbx
        ; pop r12
        ; pop r13
        ; pop r14
        ; pop r15
        ; ret
    );

    dynasm!(ops
        ; .align 16
        ; =>fscal_mask
        ; .u64 0x80F0_0000_0000_0000u64
        ; .u64 0x80F0_0000_0000_0000u64
    );

    dynasm!(ops
        ; .align 8
        ; =>jump_table
    );
    for _ in 0..=labels.len() {
        dynasm!(ops
            ; .u64 0
        );
    }

    let jump_table_offset = ops
        .labels()
        .resolve_dynamic(jump_table)
        .map_err(|_| RandomXError::AllocationFailed("jit label"))?
        .0;
    let mut jump_targets = Vec::with_capacity(labels.len() + 1);
    for label in labels.iter() {
        let offset = ops
            .labels()
            .resolve_dynamic(*label)
            .map_err(|_| RandomXError::AllocationFailed("jit label"))?
            .0;
        jump_targets.push(offset);
    }
    let exit_offset = ops
        .labels()
        .resolve_dynamic(exit)
        .map_err(|_| RandomXError::AllocationFailed("jit label"))?
        .0;
    jump_targets.push(exit_offset);

    let exec = ops
        .finalize()
        .map_err(|_| RandomXError::AllocationFailed("jit finalize"))?;
    let mut exec_bytes = exec.to_vec();
    let mut buffer = ExecutableBuffer::new(exec_bytes.len())?;
    let base_ptr = unsafe { buffer.as_fn_ptr::<*const u8>() } as usize;
    for (idx, target) in jump_targets.iter().enumerate() {
        let addr = base_ptr.wrapping_add(*target);
        let offset = jump_table_offset + (idx * 8);
        exec_bytes[offset..offset + 8].copy_from_slice(&addr.to_le_bytes());
    }
    buffer.write(&exec_bytes)?;
    buffer.finalize_rx()?;
    let entry_ptr = unsafe { buffer.as_fn_ptr::<JitFn>() };
    Ok(JitProgram {
        _buffer: buffer,
        entry: entry_ptr,
        _instructions: instructions,
        #[cfg(feature = "bench-instrument")]
        instr_mix: InstructionMix::default(),
    })
}

#[cfg(test)]
/// Compile a single instruction into a minimal JIT program (test helper).
pub fn compile_single(instr: &Instruction) -> Result<JitProgram> {
    let offsets = JitOffsets::new();
    let instructions = vec![*instr];
    let mut ops = Assembler::new().map_err(|_| RandomXError::AllocationFailed("jit assembler"))?;

    dynasm!(ops
        ; .arch x64
        ; push r15
        ; push r14
    );
    #[cfg(target_os = "windows")]
    dynasm!(ops
        ; mov r15, rcx
        ; mov r14, QWORD [r15 + offsets.r]
        ; sub rsp, 0x28
    );
    #[cfg(not(target_os = "windows"))]
    dynasm!(ops
        ; mov r15, rdi
        ; mov r14, QWORD [r15 + offsets.r]
        ; sub rsp, 0x8
    );

    // Integer instruction semantics follow docs/randomx-refs/specs.md 5.2.
    match instr.kind {
        InstructionKind::IAddRs => emit_iadd_rs(&mut ops, &offsets, instr, 0),
        InstructionKind::IXorR => emit_int_binop(&mut ops, &offsets, instr, 0, IntOp::Xor),
        InstructionKind::IRorR => emit_rot(&mut ops, &offsets, instr, 0, true),
        InstructionKind::IRolR => emit_rot(&mut ops, &offsets, instr, 0, false),
        _ => {
            return Err(RandomXError::Unsupported(
                "jit single instruction not supported",
            ))
        }
    }

    #[cfg(target_os = "windows")]
    dynasm!(ops
        ; ldmxcsr DWORD [r15 + offsets.saved_mxcsr]
        ; add rsp, 0x28
    );
    #[cfg(not(target_os = "windows"))]
    dynasm!(ops
        ; ldmxcsr DWORD [r15 + offsets.saved_mxcsr]
        ; add rsp, 0x8
    );
    dynasm!(ops
        ; pop r14
        ; pop r15
        ; ret
    );

    let exec = ops
        .finalize()
        .map_err(|_| RandomXError::AllocationFailed("jit finalize"))?;
    let mut buffer = ExecutableBuffer::new(exec.len())?;
    buffer.write(&exec)?;
    buffer.finalize_rx()?;
    let entry_ptr = unsafe { buffer.as_fn_ptr::<JitFn>() };
    Ok(JitProgram {
        _buffer: buffer,
        entry: entry_ptr,
        _instructions: instructions,
        #[cfg(feature = "bench-instrument")]
        instr_mix: InstructionMix::default(),
    })
}

enum IntOp {
    Sub,
    Mul,
    Xor,
}

enum MemOp {
    Add,
    Sub,
    Mul,
    Xor,
}

fn emit_iadd_rs(ops: &mut Assembler, offsets: &JitOffsets, instr: &Instruction, idx: usize) {
    let dst = instr.dst;
    let src = instr.src;
    let shift = instr.mod_shift() as u8;
    let r_dst = dst as i32 * 8;
    let r_src = src as i32 * 8;
    let last = offsets.last_modified + (dst as i32 * 4);
    let imm = instr.imm as i32;
    dynasm!(ops
        ; mov rax, QWORD [r14 + r_dst]
    );
    if src == dst {
        dynasm!(ops
            ; mov rdx, rax
        );
    } else {
        dynasm!(ops
            ; mov rdx, QWORD [r14 + r_src]
        );
    }
    if shift != 0 {
        dynasm!(ops
            ; shl rdx, BYTE shift as i8
        );
    }
    dynasm!(ops
        ; add rax, rdx
    );
    if dst == 5 {
        dynasm!(ops
            ; add rax, DWORD imm
        );
    }
    dynasm!(ops
        ; mov QWORD [r14 + r_dst], rax
        ; mov DWORD [r15 + last], DWORD idx as i32
    );
}

fn emit_int_binop(
    ops: &mut Assembler,
    offsets: &JitOffsets,
    instr: &Instruction,
    idx: usize,
    op: IntOp,
) {
    let dst = instr.dst;
    let src = instr.src;
    let r_dst = dst as i32 * 8;
    let last = offsets.last_modified + (dst as i32 * 4);
    dynasm!(ops
        ; mov rax, QWORD [r14 + r_dst]
    );
    if src == dst {
        let imm = instr.imm as i32;
        dynasm!(ops
            ; mov rdx, QWORD imm as i64
        );
    } else {
        let r_src = src as i32 * 8;
        dynasm!(ops
            ; mov rdx, QWORD [r14 + r_src]
        );
    }
    match op {
        IntOp::Sub => dynasm!(ops ; sub rax, rdx),
        IntOp::Mul => dynasm!(ops ; imul rax, rdx),
        IntOp::Xor => dynasm!(ops ; xor rax, rdx),
    }
    dynasm!(ops
        ; mov QWORD [r14 + r_dst], rax
        ; mov DWORD [r15 + last], DWORD idx as i32
    );
}

fn emit_mem_read_op(
    ops: &mut Assembler,
    offsets: &JitOffsets,
    instr: &Instruction,
    idx: usize,
    op: MemOp,
) {
    // Scratchpad level selection follows docs/randomx-refs/specs.md §5.1.4.
    let dst = instr.dst;
    let src = instr.src;
    let r_dst = dst as i32 * 8;
    let last = offsets.last_modified + (dst as i32 * 4);
    let mask_off = if dst == src {
        offsets.mask_l3
    } else if instr.mod_mem() == 0 {
        offsets.mask_l2
    } else {
        offsets.mask_l1
    };
    let imm = instr.imm as i32;
    dynasm!(ops
        ; mov rax, QWORD [r14 + r_dst]
    );
    if src == dst {
        dynasm!(ops
            ; xor rdx, rdx
        );
    } else {
        let r_src = src as i32 * 8;
        dynasm!(ops
            ; mov rdx, QWORD [r14 + r_src]
        );
    }
    dynasm!(ops
        ; add rdx, DWORD imm
        ; mov r9, QWORD [r15 + mask_off]
        ; and rdx, r9
    );
    let skip_prefetch = ops.new_dynamic_label();
    dynasm!(ops
        ; mov r11d, DWORD [r15 + offsets.prefetch_scratchpad]
        ; test r11d, r11d
        ; jz =>skip_prefetch
        ; lea r11, [r11 + rdx]
        ; prefetcht0 [r13 + r11]
        ; =>skip_prefetch
        ; mov r10, QWORD [r13 + rdx]
    );
    match op {
        MemOp::Add => dynasm!(ops ; add rax, r10),
        MemOp::Sub => dynasm!(ops ; sub rax, r10),
        MemOp::Mul => dynasm!(ops ; imul rax, r10),
        MemOp::Xor => dynasm!(ops ; xor rax, r10),
    }
    dynasm!(ops
        ; mov QWORD [r14 + r_dst], rax
        ; mov DWORD [r15 + last], DWORD idx as i32
    );
}

fn emit_mulh_reg(
    ops: &mut Assembler,
    offsets: &JitOffsets,
    instr: &Instruction,
    idx: usize,
    signed: bool,
) {
    let dst = instr.dst;
    let src = instr.src;
    let r_dst = dst as i32 * 8;
    let r_src = src as i32 * 8;
    let last = offsets.last_modified + (dst as i32 * 4);
    dynasm!(ops
        ; mov rax, QWORD [r14 + r_dst]
        ; mov r10, QWORD [r14 + r_src]
    );
    if signed {
        dynasm!(ops
            ; imul r10
        );
    } else {
        dynasm!(ops
            ; mul r10
        );
    }
    dynasm!(ops
        ; mov rax, rdx
        ; mov QWORD [r14 + r_dst], rax
        ; mov DWORD [r15 + last], DWORD idx as i32
    );
}

fn emit_mulh_mem(
    ops: &mut Assembler,
    offsets: &JitOffsets,
    instr: &Instruction,
    idx: usize,
    signed: bool,
) {
    let dst = instr.dst;
    let src = instr.src;
    let r_dst = dst as i32 * 8;
    let r_src = src as i32 * 8;
    let last = offsets.last_modified + (dst as i32 * 4);
    let mask_off = if dst == src {
        offsets.mask_l3
    } else if instr.mod_mem() == 0 {
        offsets.mask_l2
    } else {
        offsets.mask_l1
    };
    let imm = instr.imm as i32;
    dynasm!(ops
        ; mov rax, QWORD [r14 + r_dst]
    );
    if src == dst {
        dynasm!(ops
            ; xor rdx, rdx
        );
    } else {
        dynasm!(ops
            ; mov rdx, QWORD [r14 + r_src]
        );
    }
    dynasm!(ops
        ; add rdx, DWORD imm
        ; mov r9, QWORD [r15 + mask_off]
        ; and rdx, r9
    );
    let skip_prefetch = ops.new_dynamic_label();
    dynasm!(ops
        ; mov r11d, DWORD [r15 + offsets.prefetch_scratchpad]
        ; test r11d, r11d
        ; jz =>skip_prefetch
        ; lea r11, [r11 + rdx]
        ; prefetcht0 [r13 + r11]
        ; =>skip_prefetch
        ; mov r10, QWORD [r13 + rdx]
    );
    if signed {
        dynasm!(ops
            ; imul r10
        );
    } else {
        dynasm!(ops
            ; mul r10
        );
    }
    dynasm!(ops
        ; mov rax, rdx
        ; mov QWORD [r14 + r_dst], rax
        ; mov DWORD [r15 + last], DWORD idx as i32
    );
}

fn emit_rot(
    ops: &mut Assembler,
    offsets: &JitOffsets,
    instr: &Instruction,
    idx: usize,
    right: bool,
) {
    let dst = instr.dst;
    let src = instr.src;
    let r_dst = dst as i32 * 8;
    let last = offsets.last_modified + (dst as i32 * 4);
    dynasm!(ops
        ; mov rax, QWORD [r14 + r_dst]
    );
    if src == dst {
        let rot = (instr.imm & 63) as u8;
        if rot != 0 {
            if right {
                dynasm!(ops ; ror rax, BYTE rot as i8);
            } else {
                dynasm!(ops ; rol rax, BYTE rot as i8);
            }
        }
    } else {
        let r_src = src as i32 * 8;
        dynasm!(ops
            ; mov rcx, QWORD [r14 + r_src]
            ; and rcx, 63
        );
        if right {
            dynasm!(ops ; ror rax, cl);
        } else {
            dynasm!(ops ; rol rax, cl);
        }
    }
    dynasm!(ops
        ; mov QWORD [r14 + r_dst], rax
        ; mov DWORD [r15 + last], DWORD idx as i32
    );
}

fn emit_store(ops: &mut Assembler, offsets: &JitOffsets, instr: &Instruction) {
    let dst = instr.dst;
    let src = instr.src;
    let r_dst = dst as i32 * 8;
    let r_src = src as i32 * 8;
    let mask_off = if instr.mod_cond() >= 14 {
        offsets.mask_l3
    } else if instr.mod_mem() == 0 {
        offsets.mask_l2
    } else {
        offsets.mask_l1
    };
    let imm = instr.imm as i32;
    dynasm!(ops
        ; mov rax, QWORD [r14 + r_dst]
        ; mov rdx, QWORD [r14 + r_src]
        ; add rax, DWORD imm
        ; mov r9, QWORD [r15 + mask_off]
        ; and rax, r9
        ; mov QWORD [r13 + rax], rdx
    );
}

// Float ops are inlined for both JIT paths; helpers remain for tests.

fn emit_call_prepare(ops: &mut Assembler) {
    #[cfg(target_os = "windows")]
    dynasm!(ops
        ; mov rcx, r15
        ; mov rax, QWORD jit_prepare_iteration as *const () as i64
        ; call rax
    );
    #[cfg(not(target_os = "windows"))]
    dynasm!(ops
        ; mov rdi, r15
        ; mov rax, QWORD jit_prepare_iteration as *const () as i64
        ; call rax
    );
}

fn emit_call_finish(ops: &mut Assembler) {
    #[cfg(target_os = "windows")]
    dynasm!(ops
        ; mov rcx, r15
        ; mov rax, QWORD jit_finish_iteration as *const () as i64
        ; call rax
    );
    #[cfg(not(target_os = "windows"))]
    dynasm!(ops
        ; mov rdi, r15
        ; mov rax, QWORD jit_finish_iteration as *const () as i64
        ; call rax
    );
}

#[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
fn emit_call_monotonic_ns(ops: &mut Assembler) {
    for (slot, idx) in FAST_REGS_VOLATILE.iter().enumerate() {
        let reg = reg_for(*idx);
        let off = FAST_REGS_SPILL_BASE + (slot as i32) * 8;
        dynasm!(ops
            ; mov QWORD [rsp + off], Rq(reg)
        );
    }
    dynasm!(ops
        ; mov rax, QWORD jit_monotonic_ns as *const () as i64
        ; call rax
    );
    for (slot, idx) in FAST_REGS_VOLATILE.iter().enumerate() {
        let reg = reg_for(*idx);
        let off = FAST_REGS_SPILL_BASE + (slot as i32) * 8;
        dynasm!(ops
            ; mov Rq(reg), QWORD [rsp + off]
        );
    }
}

fn emit_set_mxcsr_from_fprc(ops: &mut Assembler, offsets: &JitOffsets) {
    dynasm!(ops
        ; mov eax, DWORD [r15 + offsets.fprc]
        ; stmxcsr DWORD [rsp]
        ; mov edx, DWORD [rsp]
        ; and edx, DWORD 0xFFFF9FFFu32 as i32
        ; shl eax, 13
        ; or edx, eax
        ; mov DWORD [rsp], edx
        ; ldmxcsr DWORD [rsp]
    );
}

fn emit_apply_e_mask_bits(ops: &mut Assembler) {
    dynasm!(ops
        ; shl rax, 1
        ; shr rax, 1
        ; mov rcx, rax
        ; shr rcx, 52
        ; and rcx, 0x7ff
        ; and rcx, 0xF80
        ; shl r11, 3
        ; or rcx, r11
        ; or rcx, 0x3
        ; shl rax, 12
        ; shr rax, 12
        ; shr rax, 22
        ; shl rax, 22
        ; and rdx, 0x3FFFFF
        ; or rax, rdx
        ; shl rcx, 52
        ; or rax, rcx
    );
}

fn emit_set_last_modified(ops: &mut Assembler, offsets: &JitOffsets, ip: usize) {
    dynasm!(ops
        ; mov edx, DWORD ip as i32
    );
    for idx in 0..8 {
        let last = offsets.last_modified + (idx * 4);
        dynasm!(ops
            ; mov DWORD [r15 + last], edx
        );
    }
}

#[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
fn emit_fastregs_perf_add(ops: &mut Assembler, offset: i32, value: i32) {
    dynasm!(ops
        ; add QWORD [r15 + offset], value
    );
}

#[cfg(feature = "jit-fastregs")]
fn emit_float_swap_inline(ops: &mut Assembler, offsets: &JitOffsets, idx: usize, use_e: bool) {
    let base_off = if use_e { offsets.e } else { offsets.f };
    let reg_off = (idx as i32) * 16;
    dynasm!(ops
        ; mov r11, QWORD [r15 + base_off]
        ; movupd xmm0, [r11 + reg_off]
        ; shufpd xmm0, xmm0, 0x1
        ; movupd [r11 + reg_off], xmm0
    );
}

// Conservative JIT cached bases: rbx=f, rbp=e, r12=a, r13=scratchpad.
fn emit_float_swap_inline_cached(ops: &mut Assembler, idx: usize, use_e: bool) {
    let reg_off = (idx as i32) * 16;
    if use_e {
        dynasm!(ops
            ; movupd xmm0, [rbp + reg_off]
            ; shufpd xmm0, xmm0, 0x1
            ; movupd [rbp + reg_off], xmm0
        );
    } else {
        dynasm!(ops
            ; movupd xmm0, [rbx + reg_off]
            ; shufpd xmm0, xmm0, 0x1
            ; movupd [rbx + reg_off], xmm0
        );
    }
}

#[cfg(feature = "jit-fastregs")]
fn emit_float_add_sub_r_inline(
    ops: &mut Assembler,
    offsets: &JitOffsets,
    instr: &Instruction,
    add: bool,
) {
    let dst = instr.dst & 3;
    let src = instr.src & 3;
    let dst_off = (dst as i32) * 16;
    let src_off = (src as i32) * 16;
    dynasm!(ops
        ; mov r11, QWORD [r15 + offsets.f]
        ; movupd xmm0, [r11 + dst_off]
        ; mov rcx, QWORD [r15 + offsets.a]
        ; movupd xmm1, [rcx + src_off]
    );
    if add {
        dynasm!(ops ; addpd xmm0, xmm1);
    } else {
        dynasm!(ops ; subpd xmm0, xmm1);
    }
    dynasm!(ops
        ; mov r11, QWORD [r15 + offsets.f]
        ; movupd [r11 + dst_off], xmm0
    );
}

fn emit_float_add_sub_r_inline_cached(ops: &mut Assembler, instr: &Instruction, add: bool) {
    let dst = instr.dst & 3;
    let src = instr.src & 3;
    let dst_off = (dst as i32) * 16;
    let src_off = (src as i32) * 16;
    dynasm!(ops
        ; movupd xmm0, [rbx + dst_off]
        ; movupd xmm1, [r12 + src_off]
    );
    if add {
        dynasm!(ops ; addpd xmm0, xmm1);
    } else {
        dynasm!(ops ; subpd xmm0, xmm1);
    }
    dynasm!(ops
        ; movupd [rbx + dst_off], xmm0
    );
}

#[cfg(feature = "jit-fastregs")]
fn emit_float_scal_inline(
    ops: &mut Assembler,
    offsets: &JitOffsets,
    instr: &Instruction,
    fscal_mask: DynamicLabel,
) {
    let dst = instr.dst & 3;
    let dst_off = (dst as i32) * 16;
    dynasm!(ops
        ; mov r11, QWORD [r15 + offsets.f]
        ; movupd xmm0, [r11 + dst_off]
        ; movupd xmm1, [=>fscal_mask]
        ; xorpd xmm0, xmm1
        ; movupd [r11 + dst_off], xmm0
    );
}

fn emit_float_scal_inline_cached(
    ops: &mut Assembler,
    instr: &Instruction,
    fscal_mask: DynamicLabel,
) {
    let dst = instr.dst & 3;
    let dst_off = (dst as i32) * 16;
    dynasm!(ops
        ; movupd xmm0, [rbx + dst_off]
        ; movupd xmm1, [=>fscal_mask]
        ; xorpd xmm0, xmm1
        ; movupd [rbx + dst_off], xmm0
    );
}

#[cfg(feature = "jit-fastregs")]
fn emit_float_mul_r_inline(ops: &mut Assembler, offsets: &JitOffsets, instr: &Instruction) {
    let dst = instr.dst & 3;
    let src = instr.src & 3;
    let dst_off = (dst as i32) * 16;
    let src_off = (src as i32) * 16;
    dynasm!(ops
        ; mov r11, QWORD [r15 + offsets.e]
        ; movupd xmm0, [r11 + dst_off]
        ; mov rcx, QWORD [r15 + offsets.a]
        ; movupd xmm1, [rcx + src_off]
        ; mulpd xmm0, xmm1
        ; mov r11, QWORD [r15 + offsets.e]
        ; movupd [r11 + dst_off], xmm0
    );
}

fn emit_float_mul_r_inline_cached(ops: &mut Assembler, instr: &Instruction) {
    let dst = instr.dst & 3;
    let src = instr.src & 3;
    let dst_off = (dst as i32) * 16;
    let src_off = (src as i32) * 16;
    dynasm!(ops
        ; movupd xmm0, [rbp + dst_off]
        ; movupd xmm1, [r12 + src_off]
        ; mulpd xmm0, xmm1
        ; movupd [rbp + dst_off], xmm0
    );
}

#[cfg(feature = "jit-fastregs")]
fn emit_float_sqrt_r_inline(ops: &mut Assembler, offsets: &JitOffsets, instr: &Instruction) {
    let dst = instr.dst & 3;
    let dst_off = (dst as i32) * 16;
    dynasm!(ops
        ; mov r11, QWORD [r15 + offsets.e]
        ; movupd xmm0, [r11 + dst_off]
        ; sqrtpd xmm0, xmm0
        ; movupd [r11 + dst_off], xmm0
    );
}

fn emit_float_sqrt_r_inline_cached(ops: &mut Assembler, instr: &Instruction) {
    let dst = instr.dst & 3;
    let dst_off = (dst as i32) * 16;
    dynasm!(ops
        ; movupd xmm0, [rbp + dst_off]
        ; sqrtpd xmm0, xmm0
        ; movupd [rbp + dst_off], xmm0
    );
}

fn emit_float_mem_base_from_regfile(ops: &mut Assembler, instr: &Instruction) {
    let src_off = (instr.src as i32) * 8;
    dynasm!(ops
        ; mov rax, QWORD [r14 + src_off]
    );
}

#[cfg(feature = "jit-fastregs")]
fn emit_float_mem_base_from_fastreg(ops: &mut Assembler, instr: &Instruction) {
    let src_reg = reg_for(instr.src);
    dynasm!(ops
        ; mov rax, Rq(src_reg)
    );
}

fn emit_float_add_sub_m_body_cached(
    ops: &mut Assembler,
    offsets: &JitOffsets,
    instr: &Instruction,
    add: bool,
) {
    let dst = instr.dst & 3;
    let dst_off = (dst as i32) * 16;
    let mask_off = if instr.mod_mem() == 0 {
        offsets.mask_l2
    } else {
        offsets.mask_l1
    };
    let imm = instr.imm as i32;
    dynasm!(ops
        ; add rax, DWORD imm
        ; mov rcx, QWORD [r15 + mask_off]
        ; and rax, rcx
    );
    let skip_prefetch = ops.new_dynamic_label();
    dynasm!(ops
        ; mov r11d, DWORD [r15 + offsets.prefetch_scratchpad]
        ; test r11d, r11d
        ; jz =>skip_prefetch
        ; lea r11, [r11 + rax]
        ; prefetcht0 [r13 + r11]
        ; =>skip_prefetch
        ; movq xmm0, QWORD [r13 + rax]
        ; cvtdq2pd xmm0, xmm0
        ; movupd xmm1, [rbx + dst_off]
    );
    if add {
        dynasm!(ops ; addpd xmm1, xmm0);
    } else {
        dynasm!(ops ; subpd xmm1, xmm0);
    }
    dynasm!(ops
        ; movupd [rbx + dst_off], xmm1
    );
}

#[cfg(feature = "jit-fastregs")]
fn emit_float_add_sub_m_body(
    ops: &mut Assembler,
    offsets: &JitOffsets,
    instr: &Instruction,
    add: bool,
) {
    let dst = instr.dst & 3;
    let dst_off = (dst as i32) * 16;
    let mask_off = if instr.mod_mem() == 0 {
        offsets.mask_l2
    } else {
        offsets.mask_l1
    };
    let imm = instr.imm as i32;
    dynasm!(ops
        ; add rax, DWORD imm
        ; mov rcx, QWORD [r15 + mask_off]
        ; and rax, rcx
        ; mov r11, QWORD [r15 + offsets.scratchpad]
    );
    let skip_prefetch = ops.new_dynamic_label();
    dynasm!(ops
        ; mov ecx, DWORD [r15 + offsets.prefetch_scratchpad]
        ; test ecx, ecx
        ; jz =>skip_prefetch
        ; lea rcx, [rcx + rax]
        ; prefetcht0 [r11 + rcx]
        ; =>skip_prefetch
        ; movq xmm0, QWORD [r11 + rax]
        ; cvtdq2pd xmm0, xmm0
        ; mov r11, QWORD [r15 + offsets.f]
        ; movupd xmm1, [r11 + dst_off]
    );
    if add {
        dynasm!(ops ; addpd xmm1, xmm0);
    } else {
        dynasm!(ops ; subpd xmm1, xmm0);
    }
    dynasm!(ops
        ; movupd [r11 + dst_off], xmm1
    );
}

fn emit_float_div_m_body_cached(ops: &mut Assembler, offsets: &JitOffsets, instr: &Instruction) {
    let dst = instr.dst & 3;
    let dst_off = (dst as i32) * 16;
    let mask_off = if instr.mod_mem() == 0 {
        offsets.mask_l2
    } else {
        offsets.mask_l1
    };
    let imm = instr.imm as i32;
    dynasm!(ops
        ; add rax, DWORD imm
        ; mov rcx, QWORD [r15 + mask_off]
        ; and rax, rcx
    );
    let skip_prefetch = ops.new_dynamic_label();
    dynasm!(ops
        ; mov r11d, DWORD [r15 + offsets.prefetch_scratchpad]
        ; test r11d, r11d
        ; jz =>skip_prefetch
        ; lea r11, [r11 + rax]
        ; prefetcht0 [r13 + r11]
        ; =>skip_prefetch
        ; movq xmm0, QWORD [r13 + rax]
        ; cvtdq2pd xmm0, xmm0
        ; movapd xmm2, xmm0
        ; movq rax, xmm2
        ; mov edx, DWORD [r15 + offsets.e_mask_low]
        ; movzx r11d, BYTE [r15 + offsets.e_mask_low + 4]
    );
    emit_apply_e_mask_bits(ops);
    dynasm!(ops
        ; movq xmm0, rax
        ; movapd xmm1, xmm2
        ; movhlps xmm1, xmm1
        ; movq rax, xmm1
        ; mov edx, DWORD [r15 + offsets.e_mask_high]
        ; movzx r11d, BYTE [r15 + offsets.e_mask_high + 4]
    );
    emit_apply_e_mask_bits(ops);
    dynasm!(ops
        ; movq xmm1, rax
        ; movlhps xmm0, xmm1
        ; movupd xmm2, [rbp + dst_off]
        ; divpd xmm2, xmm0
        ; movupd [rbp + dst_off], xmm2
    );
}

#[cfg(feature = "jit-fastregs")]
fn emit_float_div_m_body(ops: &mut Assembler, offsets: &JitOffsets, instr: &Instruction) {
    let dst = instr.dst & 3;
    let dst_off = (dst as i32) * 16;
    let mask_off = if instr.mod_mem() == 0 {
        offsets.mask_l2
    } else {
        offsets.mask_l1
    };
    let imm = instr.imm as i32;
    dynasm!(ops
        ; add rax, DWORD imm
        ; mov rcx, QWORD [r15 + mask_off]
        ; and rax, rcx
        ; mov r11, QWORD [r15 + offsets.scratchpad]
    );
    let skip_prefetch = ops.new_dynamic_label();
    dynasm!(ops
        ; mov ecx, DWORD [r15 + offsets.prefetch_scratchpad]
        ; test ecx, ecx
        ; jz =>skip_prefetch
        ; lea rcx, [rcx + rax]
        ; prefetcht0 [r11 + rcx]
        ; =>skip_prefetch
        ; movq xmm0, QWORD [r11 + rax]
        ; cvtdq2pd xmm0, xmm0
        ; movapd xmm2, xmm0
        ; movq rax, xmm2
        ; mov edx, DWORD [r15 + offsets.e_mask_low]
        ; movzx r11d, BYTE [r15 + offsets.e_mask_low + 4]
    );
    emit_apply_e_mask_bits(ops);
    dynasm!(ops
        ; movq xmm0, rax
        ; movapd xmm1, xmm2
        ; movhlps xmm1, xmm1
        ; movq rax, xmm1
        ; mov edx, DWORD [r15 + offsets.e_mask_high]
        ; movzx r11d, BYTE [r15 + offsets.e_mask_high + 4]
    );
    emit_apply_e_mask_bits(ops);
    dynasm!(ops
        ; movq xmm1, rax
        ; movlhps xmm0, xmm1
        ; mov r11, QWORD [r15 + offsets.e]
        ; movupd xmm2, [r11 + dst_off]
        ; divpd xmm2, xmm0
        ; movupd [r11 + dst_off], xmm2
    );
}

#[cfg(feature = "jit-fastregs")]
#[allow(dead_code)]
fn emit_float_add_sub_m_inline(
    ops: &mut Assembler,
    offsets: &JitOffsets,
    instr: &Instruction,
    add: bool,
) {
    emit_float_mem_base_from_regfile(ops, instr);
    emit_float_add_sub_m_body(ops, offsets, instr, add);
}

#[cfg(feature = "jit-fastregs")]
#[allow(dead_code)]
fn emit_float_div_m_inline(ops: &mut Assembler, offsets: &JitOffsets, instr: &Instruction) {
    emit_float_mem_base_from_regfile(ops, instr);
    emit_float_div_m_body(ops, offsets, instr);
}

fn emit_float_add_sub_m_inline_cached(
    ops: &mut Assembler,
    offsets: &JitOffsets,
    instr: &Instruction,
    add: bool,
) {
    emit_float_mem_base_from_regfile(ops, instr);
    emit_float_add_sub_m_body_cached(ops, offsets, instr, add);
}

fn emit_float_div_m_inline_cached(ops: &mut Assembler, offsets: &JitOffsets, instr: &Instruction) {
    emit_float_mem_base_from_regfile(ops, instr);
    emit_float_div_m_body_cached(ops, offsets, instr);
}

#[cfg(feature = "jit-fastregs")]
fn emit_float_add_sub_m_inline_fast(
    ops: &mut Assembler,
    offsets: &JitOffsets,
    instr: &Instruction,
    add: bool,
) {
    emit_float_mem_base_from_fastreg(ops, instr);
    emit_float_add_sub_m_body(ops, offsets, instr, add);
}

#[cfg(feature = "jit-fastregs")]
fn emit_float_div_m_inline_fast(ops: &mut Assembler, offsets: &JitOffsets, instr: &Instruction) {
    emit_float_mem_base_from_fastreg(ops, instr);
    emit_float_div_m_body(ops, offsets, instr);
}

fn emit_cbranch_inline(
    ops: &mut Assembler,
    offsets: &JitOffsets,
    instr: &Instruction,
    ip: usize,
    jump_table: DynamicLabel,
) {
    let dst = instr.dst;
    let r_dst = dst as i32 * 8;
    let last = offsets.last_modified + (dst as i32 * 4);
    let mod_cond = instr.mod_cond() as i32;
    let imm = instr.imm as i32 as i64;
    let skip_clear = ops.new_dynamic_label();
    let no_jump = ops.new_dynamic_label();
    let target_zero = ops.new_dynamic_label();
    let have_target = ops.new_dynamic_label();

    dynasm!(ops
        ; mov rax, QWORD [r14 + r_dst]
        ; mov ecx, DWORD [r15 + offsets.jump_offset]
        ; add ecx, DWORD mod_cond
        ; mov rdx, QWORD imm
        ; test ecx, ecx
        ; jz =>skip_clear
        ; mov r8, 1
        ; lea ecx, [ecx - 1]
        ; shl r8, cl
        ; not r8
        ; and rdx, r8
        ; =>skip_clear
        ; mov ecx, DWORD [r15 + offsets.jump_offset]
        ; add ecx, DWORD mod_cond
        ; mov r8, 1
        ; shl r8, cl
        ; or rdx, r8
        ; add rax, rdx
        ; mov QWORD [r14 + r_dst], rax
        ; mov ecx, DWORD [r15 + offsets.jump_bits]
        ; mov rdx, 1
        ; shl rdx, cl
        ; dec rdx
        ; mov ecx, DWORD [r15 + offsets.jump_offset]
        ; add ecx, DWORD mod_cond
        ; shl rdx, cl
        ; mov r9d, DWORD [r15 + last]
        ; test rax, rdx
    );
    emit_set_last_modified(ops, offsets, ip);
    dynasm!(ops
        ; jnz =>no_jump
        ; cmp r9d, 0
        ; jl =>target_zero
        ; lea eax, [r9d + 1]
        ; jmp =>have_target
        ; =>target_zero
        ; xor eax, eax
        ; =>have_target
        ; lea r11, [=>jump_table]
        ; jmp QWORD [r11 + rax*8]
        ; =>no_jump
    );
}

#[cfg(feature = "jit-fastregs")]
fn emit_load_regs(ops: &mut Assembler, offsets: &JitOffsets) {
    #[cfg(feature = "bench-instrument")]
    {
        emit_fastregs_perf_add(ops, offsets.jit_fastregs_reload_count, 8);
        emit_fastregs_perf_add(ops, offsets.jit_fastregs_sync_from_ctx_count, 8);
    }
    dynasm!(ops
        ; mov r11, QWORD [r15 + offsets.r]
    );
    for i in 0..8 {
        let reg = reg_for(i);
        let off = (i as i32) * 8;
        dynasm!(ops
            ; mov Rq(reg), QWORD [r11 + off]
        );
    }
}

#[cfg(feature = "jit-fastregs")]
fn emit_store_regs(ops: &mut Assembler, offsets: &JitOffsets) {
    #[cfg(feature = "bench-instrument")]
    {
        emit_fastregs_perf_add(ops, offsets.jit_fastregs_spill_count, 8);
        emit_fastregs_perf_add(ops, offsets.jit_fastregs_sync_to_ctx_count, 8);
    }
    dynasm!(ops
        ; mov r11, QWORD [r15 + offsets.r]
    );
    for i in 0..8 {
        let reg = reg_for(i);
        let off = (i as i32) * 8;
        dynasm!(ops
            ; mov QWORD [r11 + off], Rq(reg)
        );
    }
}

#[cfg(feature = "jit-fastregs")]
fn emit_dataset_addr_from_eax(ops: &mut Assembler, offsets: &JitOffsets) {
    dynasm!(ops
        // RandomX constrains dataset_base_size to a power of two and the VM
        // clamps dataset_offset to the extra-size window, so
        // dataset_offset + (ma & (dataset_base_size - 1)) always lands inside
        // the allocated dataset. This lets the JIT use a masked byte offset
        // directly instead of two integer divisions.
        ; mov rcx, QWORD [r15 + offsets.dataset_base]
        ; dec rcx
        ; and rax, rcx
        ; add rax, QWORD [r15 + offsets.dataset_offset]
        ; and rax, MASK_L3_64
        ; mov r11, QWORD [r15 + offsets.dataset_ptr]
        ; add r11, rax
    );
}

#[cfg(feature = "jit-fastregs")]
fn emit_prepare_inline_fast(ops: &mut Assembler, offsets: &JitOffsets, read_regs: [usize; 4]) {
    #[cfg(feature = "bench-instrument")]
    {
        emit_call_monotonic_ns(ops);
        dynasm!(ops
            ; mov QWORD [r15 + offsets.jit_fastregs_stage_start_ns], rax
        );
    }

    let reg0 = reg_for(read_regs[0]);
    let reg1 = reg_for(read_regs[1]);
    dynasm!(ops
        ; mov rax, Rq(reg0)
        ; xor rax, Rq(reg1)
        ; mov edx, DWORD [r15 + offsets.sp_addr0]
        ; xor edx, eax
        ; mov DWORD [r15 + offsets.sp_addr0], edx
        ; shr rax, 32
        ; mov ecx, DWORD [r15 + offsets.sp_addr1]
        ; xor ecx, eax
        ; mov DWORD [r15 + offsets.sp_addr1], ecx
        ; mov rax, QWORD [r15 + offsets.mask_l3]
        ; and rax, MASK_L3_64
        ; and rdx, rax
        ; mov r11, QWORD [r15 + offsets.scratchpad]
        ; add r11, rdx
    );
    for i in 0..8 {
        let reg = reg_for(i);
        let off = (i as i32) * 8;
        dynasm!(ops
            ; xor Rq(reg), QWORD [r11 + off]
        );
    }

    dynasm!(ops
        ; mov eax, DWORD [r15 + offsets.sp_addr1]
        ; mov rdx, QWORD [r15 + offsets.mask_l3]
        ; and rdx, MASK_L3_64
        ; and rax, rdx
        ; mov r11, QWORD [r15 + offsets.scratchpad]
        ; add r11, rax
        ; mov rdx, QWORD [r15 + offsets.f]
    );
    for i in 0..4 {
        let sp_off = i * 8;
        let f_off = i * 16;
        dynasm!(ops
            ; movq xmm0, QWORD [r11 + sp_off]
            ; cvtdq2pd xmm0, xmm0
            ; movupd [rdx + f_off], xmm0
        );
    }

    // Optimization: preserve scratchpad address (r11) and load e[] pointer once
    // before the e-register loop. This eliminates 6 redundant instructions per
    // iteration (24 total) that were recomputing the same scratchpad address.
    //
    // Platform-specific register allocation:
    // - Windows: RSI/RDI are in FAST_REGS (hold r[2]/r[3]), so use R8/R9
    // - Non-Windows: RSI/RDI are NOT in FAST_REGS, so use them
    #[cfg(target_os = "windows")]
    dynasm!(ops
        ; mov r8, r11                            // preserve scratchpad address
        ; mov r9, QWORD [r15 + offsets.e]        // load e[] pointer once
    );
    #[cfg(not(target_os = "windows"))]
    dynasm!(ops
        ; mov rsi, r11                           // preserve scratchpad address
        ; mov rdi, QWORD [r15 + offsets.e]       // load e[] pointer once
    );

    for i in 0..4 {
        let sp_off = 32 + i * 8;
        let e_off = i * 16;
        #[cfg(target_os = "windows")]
        dynasm!(ops
            ; movq xmm0, QWORD [r8 + sp_off]     // use preserved scratchpad address
            ; cvtdq2pd xmm0, xmm0
            ; movapd xmm2, xmm0
            ; movq rax, xmm2
            ; mov edx, DWORD [r15 + offsets.e_mask_low]
            ; movzx r11d, BYTE [r15 + offsets.e_mask_low + 4]
        );
        #[cfg(not(target_os = "windows"))]
        dynasm!(ops
            ; movq xmm0, QWORD [rsi + sp_off]    // use preserved scratchpad address
            ; cvtdq2pd xmm0, xmm0
            ; movapd xmm2, xmm0
            ; movq rax, xmm2
            ; mov edx, DWORD [r15 + offsets.e_mask_low]
            ; movzx r11d, BYTE [r15 + offsets.e_mask_low + 4]
        );
        emit_apply_e_mask_bits(ops);
        #[cfg(target_os = "windows")]
        dynasm!(ops
            ; movq xmm0, rax
            ; movapd xmm1, xmm2
            ; movhlps xmm1, xmm1
            ; movq rax, xmm1
            ; mov edx, DWORD [r15 + offsets.e_mask_high]
            ; movzx r11d, BYTE [r15 + offsets.e_mask_high + 4]
        );
        #[cfg(not(target_os = "windows"))]
        dynasm!(ops
            ; movq xmm0, rax
            ; movapd xmm1, xmm2
            ; movhlps xmm1, xmm1
            ; movq rax, xmm1
            ; mov edx, DWORD [r15 + offsets.e_mask_high]
            ; movzx r11d, BYTE [r15 + offsets.e_mask_high + 4]
        );
        emit_apply_e_mask_bits(ops);
        #[cfg(target_os = "windows")]
        dynasm!(ops
            ; movq xmm1, rax
            ; movlhps xmm0, xmm1
            ; movupd [r9 + e_off], xmm0          // use preserved e[] pointer
        );
        #[cfg(not(target_os = "windows"))]
        dynasm!(ops
            ; movq xmm1, rax
            ; movlhps xmm0, xmm1
            ; movupd [rdi + e_off], xmm0         // use preserved e[] pointer
        );
    }

    dynasm!(ops
        ; mov DWORD [r15 + offsets.ip], 0
        ; mov edx, -1
    );
    for idx in 0..8 {
        let last = offsets.last_modified + (idx * 4);
        dynasm!(ops
            ; mov DWORD [r15 + last], edx
        );
    }

    #[cfg(feature = "bench-instrument")]
    {
        emit_call_monotonic_ns(ops);
        dynasm!(ops
            ; mov rdx, QWORD [r15 + offsets.jit_fastregs_stage_start_ns]
            ; sub rax, rdx
            ; add QWORD [r15 + offsets.jit_fastregs_prepare_ns], rax
        );
    }
}

#[cfg(feature = "jit-fastregs")]
fn emit_finish_inline_fast(ops: &mut Assembler, offsets: &JitOffsets, read_regs: [usize; 4]) {
    #[cfg(feature = "bench-instrument")]
    {
        emit_call_monotonic_ns(ops);
        dynasm!(ops
            ; mov QWORD [r15 + offsets.jit_fastregs_stage_start_ns], rax
        );
    }

    let cache_path = ops.new_dynamic_label();
    let done = ops.new_dynamic_label();
    let skip_prefetch = ops.new_dynamic_label();
    let tail = ops.new_dynamic_label();
    let rr2 = reg_for(read_regs[2]);
    let rr3 = reg_for(read_regs[3]);

    dynasm!(ops
        ; mov rax, Rq(rr2)
        ; xor rax, Rq(rr3)
        ; mov r11, QWORD [r15 + offsets.mx_ptr]
        ; mov edx, DWORD [r11]
        ; xor edx, eax
        ; mov DWORD [r11], edx
        ; mov eax, edx
        ; mov r11, QWORD [r15 + offsets.dataset_ptr]
        ; test r11, r11
        ; jz =>cache_path
        ; mov r11, QWORD [r15 + offsets.dataset_items]
        ; test r11, r11
        ; jz =>cache_path
        ; cmp DWORD [r15 + offsets.prefetch], 0
        ; je =>skip_prefetch
    );
    emit_dataset_addr_from_eax(ops, offsets);
    // Add prefetch distance: distance_bytes = prefetch_distance * 64
    // The prefetch field now contains the distance in cachelines (1-8)
    dynasm!(ops
        ; mov ecx, DWORD [r15 + offsets.prefetch]
        ; shl ecx, 6                              // multiply by 64 (cacheline size)
        ; add r11, rcx                            // add offset to dataset address
        ; prefetcht0 [r11]
        ; =>skip_prefetch
        ; mov r11, QWORD [r15 + offsets.ma_ptr]
        ; mov eax, DWORD [r11]
    );
    emit_dataset_addr_from_eax(ops, offsets);
    for i in 0..8 {
        let reg = reg_for(i);
        let off = (i as i32) * 8;
        dynasm!(ops
            ; xor Rq(reg), QWORD [r11 + off]
        );
    }
    dynasm!(ops
        ; jmp =>tail
        ; =>cache_path
        ; mov r11, QWORD [r15 + offsets.ma_ptr]
        ; mov eax, DWORD [r11]
        ; mov rcx, QWORD [r15 + offsets.dataset_base]
        ; dec rcx
        ; and rax, rcx
        ; add rax, QWORD [r15 + offsets.dataset_offset]
        ; shr rax, 6
    );
    #[cfg(target_os = "windows")]
    {
        let reg7 = reg_for(FAST_REGS_VOLATILE[0]);
        dynasm!(ops
            ; mov rcx, r15
            ; mov rdx, rax
            ; lea r8, [rsp + FAST_REGS_STACK_BUFFER_BASE]
            ; mov r9, Rq(reg7)
            ; mov rax, QWORD jit_compute_cache_item_words_fastregs as *const () as i64
            ; call rax
        );
    }
    #[cfg(not(target_os = "windows"))]
    {
        let reg5 = reg_for(FAST_REGS_VOLATILE[0]);
        let reg6 = reg_for(FAST_REGS_VOLATILE[1]);
        let reg7 = reg_for(FAST_REGS_VOLATILE[2]);
        dynasm!(ops
            ; mov rdi, r15
            ; mov rsi, rax
            ; lea rdx, [rsp + FAST_REGS_STACK_BUFFER_BASE]
            ; mov rcx, Rq(reg5)
            ; mov r8, Rq(reg6)
            ; mov r9, Rq(reg7)
            ; mov rax, QWORD jit_compute_cache_item_words_fastregs as *const () as i64
            ; call rax
        );
    }
    dynasm!(ops
        ; lea r11, [rsp + FAST_REGS_STACK_BUFFER_BASE]
    );
    for i in 0..8 {
        let reg = reg_for(i);
        let off = (i as i32) * 8;
        if FAST_REGS_VOLATILE.contains(&i) {
            dynasm!(ops
                ; mov Rq(reg), QWORD [r11 + off]
            );
        } else {
            dynasm!(ops
                ; xor Rq(reg), QWORD [r11 + off]
            );
        }
    }
    dynasm!(ops
        ; =>tail
        ; mov r11, QWORD [r15 + offsets.mx_ptr]
        ; mov eax, DWORD [r11]
        ; mov rcx, QWORD [r15 + offsets.ma_ptr]
        ; mov edx, DWORD [rcx]
        ; mov DWORD [r11], edx
        ; mov DWORD [rcx], eax
        ; mov eax, DWORD [r15 + offsets.sp_addr1]
        ; mov rdx, QWORD [r15 + offsets.mask_l3]
        ; and rdx, MASK_L3_64
        ; and rax, rdx
        ; mov r11, QWORD [r15 + offsets.scratchpad]
        ; add r11, rax
    );
    for i in 0..8 {
        let reg = reg_for(i);
        let off = (i as i32) * 8;
        dynasm!(ops
            ; mov rax, Rq(reg)
            ; mov QWORD [r11 + off], rax
        );
    }
    dynasm!(ops
        ; mov r11, QWORD [r15 + offsets.f]
        ; mov rdx, QWORD [r15 + offsets.e]
    );
    for i in 0..4 {
        let off = i * 16;
        dynasm!(ops
            ; movupd xmm0, [r11 + off]
            ; movupd xmm1, [rdx + off]
            ; xorpd xmm0, xmm1
            ; movupd [r11 + off], xmm0
        );
    }
    dynasm!(ops
        ; mov eax, DWORD [r15 + offsets.sp_addr0]
        ; mov rdx, QWORD [r15 + offsets.mask_l3]
        ; and rdx, MASK_L3_64
        ; and rax, rdx
        ; mov r11, QWORD [r15 + offsets.scratchpad]
        ; add r11, rax
        ; mov rdx, QWORD [r15 + offsets.f]
    );
    for i in 0..4 {
        let off = i * 16;
        dynasm!(ops
            ; movupd xmm0, [rdx + off]
            ; movupd [r11 + off], xmm0
        );
    }
    dynasm!(ops
        ; mov DWORD [r15 + offsets.sp_addr0], 0
        ; mov DWORD [r15 + offsets.sp_addr1], 0
    );
    #[cfg(feature = "bench-instrument")]
    {
        emit_call_monotonic_ns(ops);
        dynasm!(ops
            ; mov rdx, QWORD [r15 + offsets.jit_fastregs_stage_start_ns]
            ; sub rax, rdx
            ; add QWORD [r15 + offsets.jit_fastregs_finish_ns], rax
        );
    }
    dynasm!(ops
        ; jmp =>done
        ; =>done
    );
}

#[cfg(feature = "jit-fastregs")]
fn emit_iadd_rs_fast(ops: &mut Assembler, offsets: &JitOffsets, instr: &Instruction, idx: usize) {
    let dst = instr.dst;
    let src = instr.src;
    let shift = instr.mod_shift() as u8;
    let dst_reg = reg_for(dst);
    let src_reg = reg_for(src);
    let last = offsets.last_modified + (dst as i32 * 4);
    let imm = instr.imm as i32;
    dynasm!(ops
        ; mov rax, Rq(dst_reg)
    );
    if src == dst {
        dynasm!(ops
            ; mov rdx, rax
        );
    } else {
        dynasm!(ops
            ; mov rdx, Rq(src_reg)
        );
    }
    if shift != 0 {
        dynasm!(ops
            ; shl rdx, BYTE shift as i8
        );
    }
    dynasm!(ops
        ; add rax, rdx
    );
    if dst == 5 {
        dynasm!(ops
            ; add rax, DWORD imm
        );
    }
    dynasm!(ops
        ; mov Rq(dst_reg), rax
        ; mov DWORD [r15 + last], DWORD idx as i32
    );
}

#[cfg(feature = "jit-fastregs")]
fn emit_int_binop_fast(
    ops: &mut Assembler,
    offsets: &JitOffsets,
    instr: &Instruction,
    idx: usize,
    op: IntOp,
) {
    let dst = instr.dst;
    let src = instr.src;
    let dst_reg = reg_for(dst);
    let src_reg = reg_for(src);
    let last = offsets.last_modified + (dst as i32 * 4);
    dynasm!(ops
        ; mov rax, Rq(dst_reg)
    );
    if src == dst {
        let imm = instr.imm as i32;
        dynasm!(ops
            ; mov rdx, QWORD imm as i64
        );
    } else {
        dynasm!(ops
            ; mov rdx, Rq(src_reg)
        );
    }
    match op {
        IntOp::Sub => dynasm!(ops ; sub rax, rdx),
        IntOp::Mul => dynasm!(ops ; imul rax, rdx),
        IntOp::Xor => dynasm!(ops ; xor rax, rdx),
    }
    dynasm!(ops
        ; mov Rq(dst_reg), rax
        ; mov DWORD [r15 + last], DWORD idx as i32
    );
}

#[cfg(feature = "jit-fastregs")]
fn emit_mem_read_op_fast(
    ops: &mut Assembler,
    offsets: &JitOffsets,
    instr: &Instruction,
    idx: usize,
    op: MemOp,
) {
    let dst = instr.dst;
    let src = instr.src;
    let dst_reg = reg_for(dst);
    let src_reg = reg_for(src);
    let last = offsets.last_modified + (dst as i32 * 4);
    let mask_off = if dst == src {
        offsets.mask_l3
    } else if instr.mod_mem() == 0 {
        offsets.mask_l2
    } else {
        offsets.mask_l1
    };
    let imm = instr.imm as i32;
    dynasm!(ops
        ; mov rax, Rq(dst_reg)
    );
    if src == dst {
        dynasm!(ops
            ; xor rdx, rdx
        );
    } else {
        dynasm!(ops
            ; mov rdx, Rq(src_reg)
        );
    }
    dynasm!(ops
        ; add rdx, DWORD imm
        ; mov rcx, QWORD [r15 + mask_off]
        ; and rdx, rcx
        ; mov r11, QWORD [r15 + offsets.scratchpad]
    );
    let skip_prefetch = ops.new_dynamic_label();
    dynasm!(ops
        ; mov ecx, DWORD [r15 + offsets.prefetch_scratchpad]
        ; test ecx, ecx
        ; jz =>skip_prefetch
        ; lea rcx, [rcx + rdx]
        ; prefetcht0 [r11 + rcx]
        ; =>skip_prefetch
        ; mov rcx, QWORD [r11 + rdx]
    );
    match op {
        MemOp::Add => dynasm!(ops ; add rax, rcx),
        MemOp::Sub => dynasm!(ops ; sub rax, rcx),
        MemOp::Mul => dynasm!(ops ; imul rax, rcx),
        MemOp::Xor => dynasm!(ops ; xor rax, rcx),
    }
    dynasm!(ops
        ; mov Rq(dst_reg), rax
        ; mov DWORD [r15 + last], DWORD idx as i32
    );
}

#[cfg(feature = "jit-fastregs")]
fn emit_mulh_reg_fast(
    ops: &mut Assembler,
    offsets: &JitOffsets,
    instr: &Instruction,
    idx: usize,
    signed: bool,
) {
    let dst = instr.dst;
    let src = instr.src;
    let dst_reg = reg_for(dst);
    let src_reg = reg_for(src);
    let last = offsets.last_modified + (dst as i32 * 4);
    dynasm!(ops
        ; mov rax, Rq(dst_reg)
        ; mov r11, Rq(src_reg)
    );
    if signed {
        dynasm!(ops
            ; imul r11
        );
    } else {
        dynasm!(ops
            ; mul r11
        );
    }
    dynasm!(ops
        ; mov Rq(dst_reg), rdx
        ; mov DWORD [r15 + last], DWORD idx as i32
    );
}

#[cfg(feature = "jit-fastregs")]
fn emit_mulh_mem_fast(
    ops: &mut Assembler,
    offsets: &JitOffsets,
    instr: &Instruction,
    idx: usize,
    signed: bool,
) {
    let dst = instr.dst;
    let src = instr.src;
    let dst_reg = reg_for(dst);
    let src_reg = reg_for(src);
    let last = offsets.last_modified + (dst as i32 * 4);
    let mask_off = if dst == src {
        offsets.mask_l3
    } else if instr.mod_mem() == 0 {
        offsets.mask_l2
    } else {
        offsets.mask_l1
    };
    let imm = instr.imm as i32;
    dynasm!(ops
        ; mov rax, Rq(dst_reg)
    );
    if src == dst {
        dynasm!(ops
            ; xor rdx, rdx
        );
    } else {
        dynasm!(ops
            ; mov rdx, Rq(src_reg)
        );
    }
    dynasm!(ops
        ; add rdx, DWORD imm
        ; mov r11, QWORD [r15 + mask_off]
        ; and rdx, r11
        ; mov r11, QWORD [r15 + offsets.scratchpad]
    );
    let skip_prefetch = ops.new_dynamic_label();
    dynasm!(ops
        ; mov ecx, DWORD [r15 + offsets.prefetch_scratchpad]
        ; test ecx, ecx
        ; jz =>skip_prefetch
        ; lea rcx, [rcx + rdx]
        ; prefetcht0 [r11 + rcx]
        ; =>skip_prefetch
        ; mov rcx, QWORD [r11 + rdx]
    );
    if signed {
        dynasm!(ops
            ; imul rcx
        );
    } else {
        dynasm!(ops
            ; mul rcx
        );
    }
    dynasm!(ops
        ; mov Rq(dst_reg), rdx
        ; mov DWORD [r15 + last], DWORD idx as i32
    );
}

#[cfg(feature = "jit-fastregs")]
fn emit_rot_fast(
    ops: &mut Assembler,
    offsets: &JitOffsets,
    instr: &Instruction,
    idx: usize,
    right: bool,
) {
    let dst = instr.dst;
    let src = instr.src;
    let dst_reg = reg_for(dst);
    let src_reg = reg_for(src);
    let last = offsets.last_modified + (dst as i32 * 4);
    dynasm!(ops
        ; mov rax, Rq(dst_reg)
    );
    if src == dst {
        let rot = (instr.imm & 63) as u8;
        if rot != 0 {
            if right {
                dynasm!(ops ; ror rax, BYTE rot as i8);
            } else {
                dynasm!(ops ; rol rax, BYTE rot as i8);
            }
        }
    } else {
        dynasm!(ops
            ; mov rcx, Rq(src_reg)
            ; and rcx, 63
        );
        if right {
            dynasm!(ops ; ror rax, cl);
        } else {
            dynasm!(ops ; rol rax, cl);
        }
    }
    dynasm!(ops
        ; mov Rq(dst_reg), rax
        ; mov DWORD [r15 + last], DWORD idx as i32
    );
}

#[cfg(feature = "jit-fastregs")]
fn emit_store_fast(ops: &mut Assembler, offsets: &JitOffsets, instr: &Instruction) {
    let dst = instr.dst;
    let src = instr.src;
    let dst_reg = reg_for(dst);
    let src_reg = reg_for(src);
    let mask_off = if instr.mod_cond() >= 14 {
        offsets.mask_l3
    } else if instr.mod_mem() == 0 {
        offsets.mask_l2
    } else {
        offsets.mask_l1
    };
    let imm = instr.imm as i32;
    dynasm!(ops
        ; mov rax, Rq(dst_reg)
        ; mov rdx, Rq(src_reg)
        ; add rax, DWORD imm
        ; mov rcx, QWORD [r15 + mask_off]
        ; and rax, rcx
        ; mov r11, QWORD [r15 + offsets.scratchpad]
        ; mov QWORD [r11 + rax], rdx
    );
}

#[cfg(feature = "jit-fastregs")]
fn emit_cbranch_inline_fast(
    ops: &mut Assembler,
    offsets: &JitOffsets,
    instr: &Instruction,
    ip: usize,
    jump_table: DynamicLabel,
) {
    let dst = instr.dst;
    let dst_reg = reg_for(dst);
    let last = offsets.last_modified + (dst as i32 * 4);
    let mod_cond = instr.mod_cond() as i32;
    let imm = instr.imm as i32 as i64;
    let skip_clear = ops.new_dynamic_label();
    let no_jump = ops.new_dynamic_label();
    let target_zero = ops.new_dynamic_label();
    let have_target = ops.new_dynamic_label();

    dynasm!(ops
        ; mov rax, Rq(dst_reg)
        ; mov ecx, DWORD [r15 + offsets.jump_offset]
        ; add ecx, DWORD mod_cond
        ; mov rdx, QWORD imm
        ; test ecx, ecx
        ; jz =>skip_clear
        ; mov r11, 1
        ; lea ecx, [ecx - 1]
        ; shl r11, cl
        ; not r11
        ; and rdx, r11
        ; =>skip_clear
        ; mov ecx, DWORD [r15 + offsets.jump_offset]
        ; add ecx, DWORD mod_cond
        ; mov r11, 1
        ; shl r11, cl
        ; or rdx, r11
        ; add rax, rdx
        ; mov Rq(dst_reg), rax
        ; mov ecx, DWORD [r15 + offsets.jump_bits]
        ; mov rdx, 1
        ; shl rdx, cl
        ; dec rdx
        ; mov ecx, DWORD [r15 + offsets.jump_offset]
        ; add ecx, DWORD mod_cond
        ; shl rdx, cl
        ; mov r11d, DWORD [r15 + last]
        ; test rax, rdx
    );
    emit_set_last_modified(ops, offsets, ip);
    dynasm!(ops
        ; jnz =>no_jump
        ; cmp r11d, 0
        ; jl =>target_zero
        ; lea eax, [r11d + 1]
        ; jmp =>have_target
        ; =>target_zero
        ; xor eax, eax
        ; =>have_target
        ; lea r11, [=>jump_table]
        ; jmp QWORD [r11 + rax*8]
        ; =>no_jump
    );
}

#[cfg(feature = "jit-fastregs")]
#[allow(dead_code)]
fn emit_load_volatile_regs(ops: &mut Assembler, _offsets: &JitOffsets) {
    #[cfg(feature = "bench-instrument")]
    {
        let count = FAST_REGS_VOLATILE.len() as i32;
        emit_fastregs_perf_add(ops, _offsets.jit_fastregs_preserve_reload_count, count);
    }
    for (slot, idx) in FAST_REGS_VOLATILE.iter().enumerate() {
        let reg = reg_for(*idx);
        let off = FAST_REGS_SPILL_BASE + (slot as i32) * 8;
        dynasm!(ops
            ; mov Rq(reg), QWORD [rsp + off]
        );
    }
}

#[cfg(feature = "jit-fastregs")]
#[allow(dead_code)]
fn emit_store_volatile_regs(ops: &mut Assembler, _offsets: &JitOffsets) {
    #[cfg(feature = "bench-instrument")]
    {
        let count = FAST_REGS_VOLATILE.len() as i32;
        emit_fastregs_perf_add(ops, _offsets.jit_fastregs_preserve_spill_count, count);
    }
    for (slot, idx) in FAST_REGS_VOLATILE.iter().enumerate() {
        let reg = reg_for(*idx);
        let off = FAST_REGS_SPILL_BASE + (slot as i32) * 8;
        dynasm!(ops
            ; mov QWORD [rsp + off], Rq(reg)
        );
    }
}
