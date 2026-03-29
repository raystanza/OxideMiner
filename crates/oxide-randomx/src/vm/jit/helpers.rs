use super::super::{
    cbranch_cimm, imm32_signed, FpReg, Instruction, InstructionKind, RoundingModeGuard,
};
use super::VmJitContext;
#[cfg(feature = "jit-fastregs")]
use crate::dataset::compute_item_words_in_place;
use core::ptr;
use core::slice;
#[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
use std::sync::OnceLock;
#[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
use std::time::Instant;

#[cfg(all(feature = "bench-instrument", feature = "jit-fastregs"))]
pub extern "C" fn jit_monotonic_ns() -> u64 {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    ORIGIN
        .get_or_init(Instant::now)
        .elapsed()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64
}

// Floating-point ops use the interpreter semantics (docs/randomx-refs/specs.md §5.3)
// and apply CFROUND rounding via the same guard (docs/randomx-refs/specs.md §5.4.1).
#[allow(dead_code)]
pub unsafe extern "C" fn jit_exec_float(ctx: *mut VmJitContext, instr: *const Instruction) {
    let ctx = unsafe { &mut *ctx };
    #[cfg(feature = "bench-instrument")]
    {
        let vm = unsafe { &mut *ctx.vm_ptr };
        vm.perf.jit_helper_calls_float = vm.perf.jit_helper_calls_float.saturating_add(1);
    }
    let instr = unsafe { &*instr };
    let r = unsafe { slice::from_raw_parts(ctx.r, 8) };
    let f = unsafe { slice::from_raw_parts_mut(ctx.f, 4) };
    let e = unsafe { slice::from_raw_parts_mut(ctx.e, 4) };
    let a = unsafe { slice::from_raw_parts(ctx.a, 4) };

    match instr.kind {
        InstructionKind::FSwapR => {
            let idx = instr.dst;
            if idx < 4 {
                f[idx] = FpReg {
                    lo: f[idx].hi,
                    hi: f[idx].lo,
                };
            } else {
                let eidx = idx - 4;
                e[eidx] = FpReg {
                    lo: e[eidx].hi,
                    hi: e[eidx].lo,
                };
            }
        }
        InstructionKind::FAddR => {
            let dst = instr.dst & 3;
            let src = instr.src & 3;
            let _guard = RoundingModeGuard::new(ctx.fprc);
            f[dst].lo += a[src].lo;
            f[dst].hi += a[src].hi;
        }
        InstructionKind::FAddM => {
            let dst = instr.dst & 3;
            let mem = read_mem_fp(ctx, r, instr.src, instr.imm, instr.mod_mem(), false);
            let _guard = RoundingModeGuard::new(ctx.fprc);
            f[dst].lo += mem.lo;
            f[dst].hi += mem.hi;
        }
        InstructionKind::FSubR => {
            let dst = instr.dst & 3;
            let src = instr.src & 3;
            let _guard = RoundingModeGuard::new(ctx.fprc);
            f[dst].lo -= a[src].lo;
            f[dst].hi -= a[src].hi;
        }
        InstructionKind::FSubM => {
            let dst = instr.dst & 3;
            let mem = read_mem_fp(ctx, r, instr.src, instr.imm, instr.mod_mem(), false);
            let _guard = RoundingModeGuard::new(ctx.fprc);
            f[dst].lo -= mem.lo;
            f[dst].hi -= mem.hi;
        }
        InstructionKind::FScalR => {
            let dst = instr.dst & 3;
            f[dst].fscal();
        }
        InstructionKind::FMulR => {
            let dst = instr.dst & 3;
            let src = instr.src & 3;
            let _guard = RoundingModeGuard::new(ctx.fprc);
            e[dst].lo *= a[src].lo;
            e[dst].hi *= a[src].hi;
        }
        InstructionKind::FDivM => {
            let dst = instr.dst & 3;
            let mem = read_mem_fp(ctx, r, instr.src, instr.imm, instr.mod_mem(), true);
            let _guard = RoundingModeGuard::new(ctx.fprc);
            e[dst].lo /= mem.lo;
            e[dst].hi /= mem.hi;
        }
        InstructionKind::FSqrtR => {
            let dst = instr.dst & 3;
            let _guard = RoundingModeGuard::new(ctx.fprc);
            e[dst].lo = e[dst].lo.sqrt();
            e[dst].hi = e[dst].hi.sqrt();
        }
        _ => {}
    }
}

#[cfg(feature = "jit-fastregs")]
#[allow(dead_code)]
pub unsafe extern "C" fn jit_exec_float_nomem_no_r(
    ctx: *mut VmJitContext,
    instr: *const Instruction,
) {
    let ctx = unsafe { &mut *ctx };
    #[cfg(feature = "bench-instrument")]
    {
        let vm = unsafe { &mut *ctx.vm_ptr };
        vm.perf.jit_helper_calls_float = vm.perf.jit_helper_calls_float.saturating_add(1);
    }
    let instr = unsafe { &*instr };
    let f = unsafe { slice::from_raw_parts_mut(ctx.f, 4) };
    let e = unsafe { slice::from_raw_parts_mut(ctx.e, 4) };
    let a = unsafe { slice::from_raw_parts(ctx.a, 4) };

    match instr.kind {
        InstructionKind::FSwapR => {
            let idx = instr.dst;
            if idx < 4 {
                f[idx] = FpReg {
                    lo: f[idx].hi,
                    hi: f[idx].lo,
                };
            } else {
                let eidx = idx - 4;
                e[eidx] = FpReg {
                    lo: e[eidx].hi,
                    hi: e[eidx].lo,
                };
            }
        }
        InstructionKind::FAddR => {
            let dst = instr.dst & 3;
            let src = instr.src & 3;
            let _guard = RoundingModeGuard::new(ctx.fprc);
            f[dst].lo += a[src].lo;
            f[dst].hi += a[src].hi;
        }
        InstructionKind::FSubR => {
            let dst = instr.dst & 3;
            let src = instr.src & 3;
            let _guard = RoundingModeGuard::new(ctx.fprc);
            f[dst].lo -= a[src].lo;
            f[dst].hi -= a[src].hi;
        }
        InstructionKind::FScalR => {
            let dst = instr.dst & 3;
            f[dst].fscal();
        }
        InstructionKind::FMulR => {
            let dst = instr.dst & 3;
            let src = instr.src & 3;
            let _guard = RoundingModeGuard::new(ctx.fprc);
            e[dst].lo *= a[src].lo;
            e[dst].hi *= a[src].hi;
        }
        InstructionKind::FSqrtR => {
            let dst = instr.dst & 3;
            let _guard = RoundingModeGuard::new(ctx.fprc);
            e[dst].lo = e[dst].lo.sqrt();
            e[dst].hi = e[dst].hi.sqrt();
        }
        _ => {}
    }
}

#[cfg(feature = "jit-fastregs")]
#[allow(dead_code)]
pub unsafe extern "C" fn jit_exec_float_mem(
    ctx: *mut VmJitContext,
    instr: *const Instruction,
    src_val: u64,
) {
    let ctx = unsafe { &mut *ctx };
    #[cfg(feature = "bench-instrument")]
    {
        let vm = unsafe { &mut *ctx.vm_ptr };
        vm.perf.jit_helper_calls_float = vm.perf.jit_helper_calls_float.saturating_add(1);
    }
    let instr = unsafe { &*instr };
    let f = unsafe { slice::from_raw_parts_mut(ctx.f, 4) };
    let e = unsafe { slice::from_raw_parts_mut(ctx.e, 4) };

    match instr.kind {
        InstructionKind::FAddM => {
            let dst = instr.dst & 3;
            let mem = read_mem_fp_base(ctx, src_val, instr.imm, instr.mod_mem(), false);
            let _guard = RoundingModeGuard::new(ctx.fprc);
            f[dst].lo += mem.lo;
            f[dst].hi += mem.hi;
        }
        InstructionKind::FSubM => {
            let dst = instr.dst & 3;
            let mem = read_mem_fp_base(ctx, src_val, instr.imm, instr.mod_mem(), false);
            let _guard = RoundingModeGuard::new(ctx.fprc);
            f[dst].lo -= mem.lo;
            f[dst].hi -= mem.hi;
        }
        InstructionKind::FDivM => {
            let dst = instr.dst & 3;
            let mem = read_mem_fp_base(ctx, src_val, instr.imm, instr.mod_mem(), true);
            let _guard = RoundingModeGuard::new(ctx.fprc);
            e[dst].lo /= mem.lo;
            e[dst].hi /= mem.hi;
        }
        _ => {}
    }
}

// CBRANCH bookkeeping matches docs/randomx-refs/specs.md §5.4.2.
#[allow(dead_code)]
pub unsafe extern "C" fn jit_exec_cbranch(
    ctx: *mut VmJitContext,
    instr: *const Instruction,
    ip: u32,
) -> u32 {
    let ctx = unsafe { &mut *ctx };
    #[cfg(feature = "bench-instrument")]
    {
        let vm = unsafe { &mut *ctx.vm_ptr };
        vm.perf.jit_helper_calls_cbranch = vm.perf.jit_helper_calls_cbranch.saturating_add(1);
    }
    let instr = unsafe { &*instr };
    let r = unsafe { slice::from_raw_parts_mut(ctx.r, 8) };
    let dst = instr.dst;
    let b = instr.mod_cond() as u32 + ctx.jump_offset;
    let cimm = cbranch_cimm(instr.imm, b);
    r[dst] = r[dst].wrapping_add(cimm);
    let mask = ((1u64 << ctx.jump_bits) - 1) << b;
    let jump = (r[dst] & mask) == 0;
    let target = if ctx.last_modified[dst] >= 0 {
        (ctx.last_modified[dst] as u32).wrapping_add(1)
    } else {
        0
    };
    for entry in ctx.last_modified.iter_mut() {
        *entry = ip as i32;
    }
    if jump {
        target
    } else {
        ip.wrapping_add(1)
    }
}

#[allow(dead_code)]
fn read_mem_fp(
    ctx: &VmJitContext,
    r: &[u64],
    src: usize,
    imm: u32,
    mod_mem: u8,
    use_e: bool,
) -> FpReg {
    read_mem_fp_base(ctx, r[src], imm, mod_mem, use_e)
}

#[allow(dead_code)]
fn read_mem_fp_base(ctx: &VmJitContext, base: u64, imm: u32, mod_mem: u8, use_e: bool) -> FpReg {
    let addr = base.wrapping_add(imm32_signed(imm));
    let mask = if mod_mem == 0 {
        ctx.mask_l2
    } else {
        ctx.mask_l1
    };
    let idx = (addr & mask) as usize;
    let ptr = unsafe { ctx.scratchpad.add(idx) as *const u64 };
    let raw = u64::from_le(unsafe { ptr::read_unaligned(ptr) });
    if use_e {
        FpReg::from_u64_pair_e(raw, &ctx.e_mask_low, &ctx.e_mask_high)
    } else {
        FpReg::from_u64_pair(raw)
    }
}

pub unsafe extern "C" fn jit_prepare_iteration(ctx: *mut VmJitContext) {
    let ctx = unsafe { &mut *ctx };
    let vm = unsafe { &mut *ctx.vm_ptr };
    vm.prepare_iteration(&mut ctx.sp_addr0, &mut ctx.sp_addr1);
    ctx.ip = 0;
    ctx.last_modified = [-1; 8];
}

pub unsafe extern "C" fn jit_finish_iteration(ctx: *mut VmJitContext) {
    let ctx = unsafe { &mut *ctx };
    let vm = unsafe { &mut *ctx.vm_ptr };
    vm.finish_iteration(&mut ctx.sp_addr0, &mut ctx.sp_addr1);
}

#[cfg(feature = "jit-fastregs")]
unsafe fn jit_compute_cache_item_words_common(
    ctx: *mut VmJitContext,
    item_number: u64,
    out: *mut u64,
) {
    let ctx = unsafe { &mut *ctx };
    #[cfg(feature = "bench-instrument")]
    let start = jit_monotonic_ns();
    let vm = unsafe { &mut *ctx.vm_ptr };
    let out_words = unsafe { &mut *(out as *mut [u64; 8]) };
    compute_item_words_in_place(&vm.cache, &vm.cfg, item_number, out_words);
    #[cfg(feature = "bench-instrument")]
    {
        let elapsed = jit_monotonic_ns().saturating_sub(start);
        ctx.jit_fastregs_call_boundary_count =
            ctx.jit_fastregs_call_boundary_count.saturating_add(1);
        ctx.jit_fastregs_light_cache_item_helper_calls = ctx
            .jit_fastregs_light_cache_item_helper_calls
            .saturating_add(1);
        ctx.jit_fastregs_light_cache_item_helper_ns = ctx
            .jit_fastregs_light_cache_item_helper_ns
            .saturating_add(elapsed);
    }
}

#[cfg(all(feature = "jit-fastregs", target_os = "windows"))]
pub unsafe extern "C" fn jit_compute_cache_item_words_fastregs(
    ctx: *mut VmJitContext,
    item_number: u64,
    out: *mut u64,
    reg7_old: u64,
) {
    unsafe {
        jit_compute_cache_item_words_common(ctx, item_number, out);
    }
    let out_words = unsafe { &mut *(out as *mut [u64; 8]) };
    out_words[7] ^= reg7_old;
}

#[cfg(all(feature = "jit-fastregs", not(target_os = "windows")))]
pub unsafe extern "C" fn jit_compute_cache_item_words_fastregs(
    ctx: *mut VmJitContext,
    item_number: u64,
    out: *mut u64,
    reg5_old: u64,
    reg6_old: u64,
    reg7_old: u64,
) {
    unsafe {
        jit_compute_cache_item_words_common(ctx, item_number, out);
    }
    let out_words = unsafe { &mut *(out as *mut [u64; 8]) };
    out_words[5] ^= reg5_old;
    out_words[6] ^= reg6_old;
    out_words[7] ^= reg7_old;
}

#[cfg(test)]
mod tests {
    use super::jit_exec_cbranch;
    #[cfg(feature = "jit-fastregs")]
    use super::jit_exec_float_mem;
    use super::VmJitContext;
    use crate::cache::RandomXCache;
    use crate::config::RandomXConfig;
    use crate::flags::RandomXFlags;
    #[cfg(feature = "jit-fastregs")]
    use crate::vm::FpReg;
    use crate::vm::{Instruction, InstructionKind, RandomXVm, RoundingModeState};

    fn make_vm() -> RandomXVm {
        let cfg = RandomXConfig::test_small();
        let cache = RandomXCache::new_dummy(&cfg);
        let flags = RandomXFlags::default();
        RandomXVm::new_light(cache, cfg, flags).expect("vm")
    }

    #[test]
    fn cbranch_helper_jump_taken_matches_interpreter() {
        let inst = Instruction::new(InstructionKind::CBranch, 0, 0, 0, 0);
        let mut vm_interp = make_vm();
        let mut vm_jit = make_vm();
        vm_interp.program = vec![inst];
        vm_jit.program = vec![inst];
        vm_interp.r[0] = 0xffff_ffff_ffff_ff00;
        vm_jit.r[0] = vm_interp.r[0];

        let mut last = [-1; 8];
        last[0] = 4;
        let mut rounding = RoundingModeState::new(vm_interp.fprc);
        let target = vm_interp.execute_instruction(0, &mut last, &mut rounding);
        let expected_next = target.unwrap_or(1) as u32;
        let expected_last = last;

        let mut ctx = VmJitContext::new(&mut vm_jit);
        ctx.last_modified[0] = 4;
        let next = unsafe { jit_exec_cbranch(&mut ctx, &inst, 0) };

        assert_eq!(next, expected_next);
        assert_eq!(ctx.last_modified, expected_last);
        assert_eq!(vm_jit.r, vm_interp.r);
    }

    #[test]
    fn cbranch_helper_no_jump_matches_interpreter() {
        let inst = Instruction::new(InstructionKind::CBranch, 0, 0, 0, 0);
        let mut vm_interp = make_vm();
        let mut vm_jit = make_vm();
        vm_interp.program = vec![inst];
        vm_jit.program = vec![inst];
        vm_interp.r[0] = 0;
        vm_jit.r[0] = 0;

        let mut last = [-1; 8];
        last[0] = 4;
        let mut rounding = RoundingModeState::new(vm_interp.fprc);
        let target = vm_interp.execute_instruction(0, &mut last, &mut rounding);
        let expected_next = target.unwrap_or(1) as u32;
        let expected_last = last;

        let mut ctx = VmJitContext::new(&mut vm_jit);
        ctx.last_modified[0] = 4;
        let next = unsafe { jit_exec_cbranch(&mut ctx, &inst, 0) };

        assert_eq!(next, expected_next);
        assert_eq!(ctx.last_modified, expected_last);
        assert_eq!(vm_jit.r, vm_interp.r);
    }

    #[cfg(feature = "jit-fastregs")]
    fn fill_scratchpad(vm: &mut RandomXVm) {
        for (idx, slot) in vm.scratchpad.as_mut_slice().iter_mut().enumerate() {
            *slot = (idx as u8).wrapping_mul(31).wrapping_add(7);
        }
    }

    #[cfg(feature = "jit-fastregs")]
    fn fp_bits(regs: &[FpReg; 4]) -> [(u64, u64); 4] {
        let mut out = [(0u64, 0u64); 4];
        for (idx, reg) in regs.iter().enumerate() {
            out[idx] = (reg.lo.to_bits(), reg.hi.to_bits());
        }
        out
    }

    #[cfg(feature = "jit-fastregs")]
    fn assert_float_mem_helper(kind: InstructionKind, mod_mem: u8) {
        let dst = 5;
        let src = 3;
        let imm = 0x1234_5678;
        let instr = Instruction::new(kind, dst, src, mod_mem, imm);

        let mut vm_interp = make_vm();
        let mut vm_jit = make_vm();
        vm_interp.program = vec![instr];
        vm_jit.program = vec![instr];

        fill_scratchpad(&mut vm_interp);
        vm_jit
            .scratchpad
            .as_mut_slice()
            .copy_from_slice(vm_interp.scratchpad.as_slice());

        let dst_idx = dst & 3;
        vm_interp.f[dst_idx] = FpReg { lo: 1.25, hi: -2.5 };
        vm_interp.e[dst_idx] = FpReg { lo: 3.75, hi: -4.5 };
        vm_jit.f = vm_interp.f;
        vm_jit.e = vm_interp.e;
        vm_interp.fprc = 1;
        vm_jit.fprc = 1;

        let src_val = 0x1234_5678_9abc_def0;
        vm_interp.r[src] = src_val;
        vm_jit.r[src] = src_val;

        let mut last = [-1; 8];
        let mut rounding = RoundingModeState::new(vm_interp.fprc);
        vm_interp.execute_instruction(0, &mut last, &mut rounding);

        let src_val = vm_jit.r[src];
        vm_jit.r[src] ^= 0x5a5a_5a5a_5a5a_5a5a;
        let mut ctx = VmJitContext::new(&mut vm_jit);
        unsafe { jit_exec_float_mem(&mut ctx, &instr, src_val) };

        assert_eq!(fp_bits(&vm_jit.f), fp_bits(&vm_interp.f));
        assert_eq!(fp_bits(&vm_jit.e), fp_bits(&vm_interp.e));
    }

    #[cfg(feature = "jit-fastregs")]
    #[test]
    fn float_mem_helper_matches_interpreter() {
        for mod_mem in [0u8, 1u8] {
            assert_float_mem_helper(InstructionKind::FAddM, mod_mem);
            assert_float_mem_helper(InstructionKind::FSubM, mod_mem);
            assert_float_mem_helper(InstructionKind::FDivM, mod_mem);
        }
    }
}
