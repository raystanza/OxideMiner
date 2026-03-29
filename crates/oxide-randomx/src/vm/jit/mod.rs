//! JIT backend for RandomX (x86_64).

#[cfg(feature = "bench-instrument")]
use super::ScratchpadLevel;
use super::{Instruction, VmJitContext};
use crate::errors::{RandomXError, Result};
use crate::flags::RandomXFlags;
#[cfg(feature = "bench-instrument")]
use crate::perf::PerfStats;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
#[cfg(feature = "bench-instrument")]
use std::time::Instant;

mod executable;
mod helpers;
#[cfg(target_arch = "x86_64")]
mod x86_64;

pub use executable::ExecutableBuffer;

type JitFn = unsafe extern "C" fn(*mut VmJitContext);

/// JIT cache and compile statistics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct JitStats {
    pub compiles: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_evictions: u64,
    pub compile_ns: u64,
}

#[cfg(feature = "bench-instrument")]
#[derive(Clone, Copy, Debug, Default)]
struct InstructionMix {
    instr_int: u64,
    instr_float: u64,
    instr_mem: u64,
    instr_ctrl: u64,
    instr_store: u64,
    mem_read_l1: u64,
    mem_read_l2: u64,
    mem_read_l3: u64,
    mem_write_l1: u64,
    mem_write_l2: u64,
    mem_write_l3: u64,
}

#[cfg(feature = "bench-instrument")]
impl InstructionMix {
    fn from_program(program: &[Instruction]) -> Self {
        let mut mix = Self::default();
        for instr in program {
            mix.add_instr(instr);
        }
        mix
    }

    fn add_instr(&mut self, instr: &Instruction) {
        match super::instr_category(instr.kind) {
            super::InstrCategory::Mem => {
                self.instr_mem = self.instr_mem.saturating_add(1);
            }
            super::InstrCategory::Store => {
                self.instr_store = self.instr_store.saturating_add(1);
            }
            super::InstrCategory::Ctrl => {
                self.instr_ctrl = self.instr_ctrl.saturating_add(1);
            }
            super::InstrCategory::Float => {
                self.instr_float = self.instr_float.saturating_add(1);
            }
            super::InstrCategory::Int => {
                self.instr_int = self.instr_int.saturating_add(1);
            }
        }

        match instr.kind {
            super::InstructionKind::IAddM
            | super::InstructionKind::ISubM
            | super::InstructionKind::IMulM
            | super::InstructionKind::IMulH_M
            | super::InstructionKind::ISMulH_M
            | super::InstructionKind::IXorM => {
                self.record_mem_read(instr.mem_level_read(true));
            }
            super::InstructionKind::FAddM
            | super::InstructionKind::FSubM
            | super::InstructionKind::FDivM => {
                let level = if instr.mod_mem() == 0 {
                    ScratchpadLevel::L2
                } else {
                    ScratchpadLevel::L1
                };
                self.record_mem_read(level);
            }
            super::InstructionKind::IStore => {
                self.record_mem_write(instr.mem_level_write());
            }
            _ => {}
        }
    }

    fn record_mem_read(&mut self, level: ScratchpadLevel) {
        match level {
            ScratchpadLevel::L1 => {
                self.mem_read_l1 = self.mem_read_l1.saturating_add(1);
            }
            ScratchpadLevel::L2 => {
                self.mem_read_l2 = self.mem_read_l2.saturating_add(1);
            }
            ScratchpadLevel::L3 => {
                self.mem_read_l3 = self.mem_read_l3.saturating_add(1);
            }
        }
    }

    fn record_mem_write(&mut self, level: ScratchpadLevel) {
        match level {
            ScratchpadLevel::L1 => {
                self.mem_write_l1 = self.mem_write_l1.saturating_add(1);
            }
            ScratchpadLevel::L2 => {
                self.mem_write_l2 = self.mem_write_l2.saturating_add(1);
            }
            ScratchpadLevel::L3 => {
                self.mem_write_l3 = self.mem_write_l3.saturating_add(1);
            }
        }
    }

    fn add_scaled_to_perf(&self, perf: &mut PerfStats, execs: u64) {
        perf.instr_int = perf
            .instr_int
            .saturating_add(self.instr_int.saturating_mul(execs));
        perf.instr_float = perf
            .instr_float
            .saturating_add(self.instr_float.saturating_mul(execs));
        perf.instr_mem = perf
            .instr_mem
            .saturating_add(self.instr_mem.saturating_mul(execs));
        perf.instr_ctrl = perf
            .instr_ctrl
            .saturating_add(self.instr_ctrl.saturating_mul(execs));
        perf.instr_store = perf
            .instr_store
            .saturating_add(self.instr_store.saturating_mul(execs));
        perf.mem_read_l1 = perf
            .mem_read_l1
            .saturating_add(self.mem_read_l1.saturating_mul(execs));
        perf.mem_read_l2 = perf
            .mem_read_l2
            .saturating_add(self.mem_read_l2.saturating_mul(execs));
        perf.mem_read_l3 = perf
            .mem_read_l3
            .saturating_add(self.mem_read_l3.saturating_mul(execs));
        perf.mem_write_l1 = perf
            .mem_write_l1
            .saturating_add(self.mem_write_l1.saturating_mul(execs));
        perf.mem_write_l2 = perf
            .mem_write_l2
            .saturating_add(self.mem_write_l2.saturating_mul(execs));
        perf.mem_write_l3 = perf
            .mem_write_l3
            .saturating_add(self.mem_write_l3.saturating_mul(execs));
        let mem_reads =
            (self.mem_read_l1 + self.mem_read_l2 + self.mem_read_l3).saturating_mul(execs);
        let mem_writes =
            (self.mem_write_l1 + self.mem_write_l2 + self.mem_write_l3).saturating_mul(execs);
        perf.scratchpad_read_bytes = perf
            .scratchpad_read_bytes
            .saturating_add(mem_reads.saturating_mul(8));
        perf.scratchpad_write_bytes = perf
            .scratchpad_write_bytes
            .saturating_add(mem_writes.saturating_mul(8));
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct ProgramKey {
    bytes: Vec<u8>,
    flags: u32,
}

impl ProgramKey {
    fn new(bytes: &[u8], flags: u32) -> Self {
        Self {
            bytes: bytes.to_vec(),
            flags,
        }
    }
}

struct JitCache {
    entries: HashMap<ProgramKey, Arc<JitProgram>>,
    order: VecDeque<ProgramKey>,
    capacity: usize,
    stats: JitStats,
}

impl JitCache {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            capacity,
            stats: JitStats::default(),
        }
    }

    fn get(&mut self, key: &ProgramKey) -> Option<Arc<JitProgram>> {
        if let Some(entry) = self.entries.get(key) {
            self.stats.cache_hits += 1;
            return Some(entry.clone());
        }
        None
    }

    fn insert(&mut self, key: ProgramKey, program: Arc<JitProgram>) {
        if self.entries.contains_key(&key) {
            return;
        }
        if self.entries.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
                self.stats.cache_evictions += 1;
            }
        }
        self.order.push_back(key.clone());
        self.entries.insert(key, program);
    }

    fn record_compile(&mut self) {
        self.stats.compiles += 1;
    }

    fn record_miss(&mut self) {
        self.stats.cache_misses += 1;
    }

    #[cfg(feature = "bench-instrument")]
    fn record_compile_ns(&mut self, ns: u64) {
        self.stats.compile_ns = self.stats.compile_ns.saturating_add(ns);
    }

    fn stats(&self) -> JitStats {
        self.stats
    }
}

/// Compiled JIT program and its executable buffer.
pub struct JitProgram {
    _buffer: ExecutableBuffer,
    entry: JitFn,
    _instructions: Vec<Instruction>,
    #[cfg(feature = "bench-instrument")]
    instr_mix: InstructionMix,
}

impl JitProgram {
    pub(super) unsafe fn exec(&self, ctx: *mut VmJitContext) {
        unsafe { (self.entry)(ctx) };
    }

    #[cfg(feature = "bench-instrument")]
    pub(super) fn add_instr_counts(&self, perf: &mut PerfStats, execs: u64) {
        self.instr_mix.add_scaled_to_perf(perf, execs);
    }
}

pub(super) struct JitEngine {
    supported: bool,
    cache: Mutex<JitCache>,
}

impl JitEngine {
    pub(super) fn new() -> Self {
        Self::with_capacity(256)
    }

    pub(super) fn with_capacity(capacity: usize) -> Self {
        let supported = cfg!(all(
            target_arch = "x86_64",
            any(
                target_os = "windows",
                target_os = "linux",
                target_os = "macos"
            )
        ));
        Self {
            supported,
            cache: Mutex::new(JitCache::new(capacity)),
        }
    }

    pub(super) fn is_supported(&self) -> bool {
        self.supported
    }

    pub(super) fn get_or_compile(
        &self,
        program_bytes: &[u8],
        program: &[Instruction],
        flags: &RandomXFlags,
    ) -> Result<Arc<JitProgram>> {
        if !self.supported {
            return Err(RandomXError::Unsupported("jit not supported"));
        }
        let key = ProgramKey::new(program_bytes, key_flags(flags));
        {
            let mut cache = self.cache.lock().expect("jit cache");
            if let Some(entry) = cache.get(&key) {
                return Ok(entry);
            }
            cache.record_miss();
        }
        #[cfg(feature = "bench-instrument")]
        let start = Instant::now();
        let compiled = Arc::new(compile_program(program_bytes, program, flags)?);
        #[cfg(feature = "bench-instrument")]
        let elapsed = start.elapsed().as_nanos() as u64;
        let mut cache = self.cache.lock().expect("jit cache");
        if let Some(entry) = cache.entries.get(&key).cloned() {
            return Ok(entry);
        }
        cache.insert(key, compiled.clone());
        cache.record_compile();
        #[cfg(feature = "bench-instrument")]
        cache.record_compile_ns(elapsed);
        Ok(compiled)
    }

    pub(super) fn stats(&self) -> JitStats {
        let cache = self.cache.lock().expect("jit cache");
        cache.stats()
    }
}

fn compile_program(
    program_bytes: &[u8],
    program: &[Instruction],
    flags: &RandomXFlags,
) -> Result<JitProgram> {
    #[cfg(target_arch = "x86_64")]
    {
        let fast_regs = cfg!(feature = "jit-fastregs") && flags.jit_fast_regs;
        let compiled = x86_64::compile(program_bytes, program, fast_regs)?;
        #[cfg(feature = "bench-instrument")]
        let compiled = {
            let mut compiled = compiled;
            compiled.instr_mix = InstructionMix::from_program(program);
            compiled
        };
        Ok(compiled)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (program, flags);
        Err(RandomXError::Unsupported("jit not supported"))
    }
}

#[cfg(test)]
pub(super) fn compile_single_for_test(instr: &Instruction) -> Result<JitProgram> {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::compile_single(instr)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = instr;
        Err(RandomXError::Unsupported("jit not supported"))
    }
}

#[cfg(test)]
mod tests {
    use super::ProgramKey;

    #[test]
    fn program_key_is_stable() {
        let a = ProgramKey::new(b"abc", 1);
        let b = ProgramKey::new(b"abc", 1);
        assert_eq!(a, b);
    }
}

fn key_flags(flags: &RandomXFlags) -> u32 {
    let mut out = 0u32;
    if flags.prefetch {
        out |= 1 << 0;
    }
    if flags.aes_ni {
        out |= 1 << 1;
    }
    if flags.soft_aes {
        out |= 1 << 2;
    }
    if flags.large_pages_plumbing {
        out |= 1 << 3;
    }
    if cfg!(feature = "jit-fastregs") && flags.jit_fast_regs {
        out |= 1 << 4;
    }
    out
}

#[cfg(all(test, feature = "jit", target_arch = "x86_64"))]
mod cache_tests {
    use super::super::{Instruction, InstructionKind};
    use super::JitEngine;
    use crate::flags::RandomXFlags;

    fn program_bytes(tag: u8) -> Vec<u8> {
        vec![tag; 128 + 8]
    }

    #[test]
    fn jit_cache_hits_are_counted() {
        let engine = JitEngine::with_capacity(2);
        if !engine.is_supported() {
            return;
        }
        let flags = RandomXFlags::default();
        let program = vec![Instruction::new(InstructionKind::INegR, 0, 0, 0, 0)];
        let bytes = program_bytes(0x11);

        engine
            .get_or_compile(&bytes, &program, &flags)
            .expect("compile");
        engine
            .get_or_compile(&bytes, &program, &flags)
            .expect("cache hit");

        let stats = engine.stats();
        assert_eq!(stats.compiles, 1);
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.cache_misses, 1);
    }

    #[test]
    fn jit_cache_evictions_are_counted() {
        let engine = JitEngine::with_capacity(1);
        if !engine.is_supported() {
            return;
        }
        let flags = RandomXFlags::default();
        let program_a = vec![Instruction::new(InstructionKind::INegR, 0, 0, 0, 0)];
        let program_b = vec![Instruction::new(InstructionKind::IXorR, 1, 1, 0, 1)];
        engine
            .get_or_compile(&program_bytes(0x11), &program_a, &flags)
            .expect("compile a");
        engine
            .get_or_compile(&program_bytes(0x22), &program_b, &flags)
            .expect("compile b");

        let stats = engine.stats();
        assert_eq!(stats.compiles, 2);
        assert_eq!(stats.cache_misses, 2);
        assert_eq!(stats.cache_evictions, 1);
    }
}

#[cfg(all(test, feature = "jit", target_arch = "x86_64"))]
mod single_inst_tests {
    use super::super::{Instruction, InstructionKind, RoundingModeState, VmJitContext};
    use super::compile_single_for_test;
    use crate::cache::RandomXCache;
    use crate::config::RandomXConfig;
    use crate::flags::RandomXFlags;
    use crate::vm::RandomXVm;

    fn make_vm() -> RandomXVm {
        let cfg = RandomXConfig::test_small();
        let cache = RandomXCache::new_dummy(&cfg);
        let flags = RandomXFlags::default();
        RandomXVm::new_light(cache, cfg, flags).expect("vm")
    }

    fn run_interp(vm: &mut RandomXVm, inst: Instruction) -> ([u64; 8], [i32; 8]) {
        vm.program = vec![inst];
        let mut last = [-1; 8];
        let mut rounding = RoundingModeState::new(vm.fprc);
        vm.execute_instruction(0, &mut last, &mut rounding);
        (vm.r, last)
    }

    fn run_jit(vm: &mut RandomXVm, inst: Instruction) -> ([u64; 8], [i32; 8]) {
        let program = compile_single_for_test(&inst).expect("jit compile single");
        let mut ctx = VmJitContext::new(vm);
        unsafe {
            program.exec(&mut ctx);
        }
        (vm.r, ctx.last_modified)
    }

    #[test]
    fn single_iadd_rs_src_eq_dst() {
        let inst = Instruction::new(InstructionKind::IAddRs, 1, 1, 0b0000_1000, 0);
        let mut vm_interp = make_vm();
        vm_interp.r[1] = 5;
        let (regs_interp, last_interp) = run_interp(&mut vm_interp, inst);

        let mut vm_jit = make_vm();
        vm_jit.r[1] = 5;
        let (regs_jit, last_jit) = run_jit(&mut vm_jit, inst);

        assert_eq!(regs_interp, regs_jit);
        assert_eq!(last_interp, last_jit);
    }

    #[test]
    fn single_ixor_src_eq_dst_uses_imm() {
        let inst = Instruction::new(InstructionKind::IXorR, 2, 2, 0, 0x55);
        let mut vm_interp = make_vm();
        vm_interp.r[2] = 0xAA;
        let (regs_interp, last_interp) = run_interp(&mut vm_interp, inst);

        let mut vm_jit = make_vm();
        vm_jit.r[2] = 0xAA;
        let (regs_jit, last_jit) = run_jit(&mut vm_jit, inst);

        assert_eq!(regs_interp, regs_jit);
        assert_eq!(last_interp, last_jit);
    }

    #[test]
    fn single_rol_src_eq_dst_uses_imm() {
        let inst = Instruction::new(InstructionKind::IRolR, 3, 3, 0, 4);
        let mut vm_interp = make_vm();
        vm_interp.r[3] = 0x1;
        let (regs_interp, last_interp) = run_interp(&mut vm_interp, inst);

        let mut vm_jit = make_vm();
        vm_jit.r[3] = 0x1;
        let (regs_jit, last_jit) = run_jit(&mut vm_jit, inst);

        assert_eq!(regs_interp, regs_jit);
        assert_eq!(last_interp, last_jit);
    }

    #[test]
    fn single_ror_src_uses_register() {
        let inst = Instruction::new(InstructionKind::IRorR, 4, 6, 0, 0);
        let mut vm_interp = make_vm();
        vm_interp.r[4] = 0x8000_0000_0000_0001;
        vm_interp.r[6] = 1;
        let (regs_interp, last_interp) = run_interp(&mut vm_interp, inst);

        let mut vm_jit = make_vm();
        vm_jit.r[4] = 0x8000_0000_0000_0001;
        vm_jit.r[6] = 1;
        let (regs_jit, last_jit) = run_jit(&mut vm_jit, inst);

        assert_eq!(regs_interp, regs_jit);
        assert_eq!(last_interp, last_jit);
    }
}
