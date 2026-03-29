use crate::prefetch_calibration::{
    apply_prefetch_calibration_for_current_host, PrefetchCalibrationApplyStatus,
    PrefetchCalibrationMode, PREFETCH_CALIBRATION_WORKLOAD_ID,
};
use crate::{
    DatasetInitOptions, PerfStats, RandomXCache, RandomXConfig, RandomXDataset, RandomXFlags,
    RandomXVm,
};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Instant;

pub const REPORT_VERSION: &str = "oxideminer-integration-v2";
pub const PURPOSE: &str =
    "Validate the supported OxideMiner-facing lifecycle through public oxide-randomx APIs. This is a lifecycle harness, not a benchmark.";
pub const PRODUCTION_FEATURES: &str = "jit jit-fastregs";
pub const VALIDATION_FEATURES: &str = "jit jit-fastregs bench-instrument";
pub const SUPPORTED_RUNTIME_PROFILES: [&str; 3] =
    ["interpreter", "jit-conservative", "jit-fastregs"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HarnessModeSelection {
    Light,
    Fast,
    Both,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeProfile {
    Interpreter,
    JitConservative,
    JitFastRegs,
}

#[derive(Clone, Debug)]
pub struct HarnessOptions {
    pub mode: HarnessModeSelection,
    pub runtime_profile: RuntimeProfile,
    pub warmup_rounds: u64,
    pub steady_rounds: u64,
    pub threads: usize,
    pub large_pages: bool,
    pub use_1gb_pages: bool,
    pub calibration: Option<PathBuf>,
    pub workload_id: String,
    pub config: RandomXConfig,
}

#[derive(Clone, Debug, Serialize)]
pub struct HarnessReport {
    pub report_version: &'static str,
    pub purpose: &'static str,
    pub build_contract: BuildContractSummary,
    pub requested_mode: String,
    pub requested_runtime_profile: String,
    pub warmup_rounds: u64,
    pub steady_rounds: u64,
    pub threads: usize,
    pub instrumented: bool,
    pub workload_id: String,
    pub calibration_path: Option<String>,
    pub requested_flags: FlagSummary,
    pub sessions: Vec<SessionReport>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BuildContractSummary {
    pub production_features: &'static str,
    pub validation_features: &'static str,
    pub supported_runtime_profiles: [&'static str; 3],
    pub compiled_features: CompiledFeatureSummary,
}

#[derive(Clone, Debug, Serialize)]
pub struct CompiledFeatureSummary {
    pub jit: bool,
    pub jit_fastregs: bool,
    pub bench_instrument: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct FlagSummary {
    pub prefetch: bool,
    pub prefetch_distance: u8,
    pub prefetch_auto_tune: bool,
    pub scratchpad_prefetch_distance: u8,
    pub large_pages: bool,
    pub use_1gb_pages: bool,
    pub jit_requested: bool,
    pub jit_fast_regs_requested: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionReport {
    pub mode: String,
    pub lifecycle: LifecycleSummary,
    pub calibration: CalibrationSummary,
    pub requested_flags: FlagSummary,
    pub effective_flags: FlagSummary,
    pub build: BuildSummary,
    pub page_backing: PageBackingSummary,
    pub steady_state: LoopSummary,
    pub telemetry: TelemetrySummary,
    pub rekey: RekeySummary,
}

#[derive(Clone, Debug, Serialize)]
pub struct LifecycleSummary {
    pub requested_runtime_profile: String,
    pub effective_runtime_profile: String,
    pub fallback_reason: Option<String>,
    pub jit: JitSummary,
    pub rekey_matches_rebuild: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct JitSummary {
    pub requested: bool,
    pub requested_fast_regs: bool,
    pub compiled_jit_support: bool,
    pub compiled_fast_regs_support: bool,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct BuildSummary {
    pub cache_init_ns: u64,
    pub dataset_init_ns: Option<u64>,
    pub vm_init_ns: u64,
    pub jit_active: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct PageBackingSummary {
    pub scratchpad: PageAllocationSummary,
    pub dataset: Option<PageAllocationSummary>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PageAllocationSummary {
    pub allocation: String,
    pub request: PageRequestSummary,
    pub realized: RealizedPageBackingSummary,
    pub realization: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PageRequestSummary {
    pub large_pages: bool,
    pub use_1gb_pages: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RealizedPageBackingSummary {
    pub large_pages: bool,
    pub huge_page_size: Option<usize>,
    pub description: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct LoopSummary {
    pub rounds: u64,
    pub input_count: usize,
    pub total_hashes: u64,
    pub elapsed_ns: u64,
    pub first_hash_hex: String,
    pub last_hash_hex: String,
    pub output_xor_hex: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct TelemetrySummary {
    pub instrumented: bool,
    pub hashes: u64,
    pub program_execs: u64,
    pub program_gen_ns: u64,
    pub prepare_iteration_ns: u64,
    pub execute_program_ns_interpreter: u64,
    pub execute_program_ns_jit: u64,
    pub finish_iteration_ns: u64,
    pub dataset_item_loads: u64,
    pub scratchpad_read_bytes: u64,
    pub scratchpad_write_bytes: u64,
    pub jit_fastregs_prepare_ns: u64,
    pub jit_fastregs_finish_ns: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CalibrationSummary {
    pub requested: bool,
    pub path: Option<String>,
    pub status: String,
    pub matched_best_prefetch_distance: Option<u8>,
    pub matched_best_ns_per_hash: Option<u64>,
    pub matched_cpu: Option<String>,
    pub matched_workload_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RekeySummary {
    pub rekey_elapsed_ns: u64,
    pub parity: RekeyParitySummary,
    pub in_place: LoopSummary,
    pub rebuild: RebuildSummary,
}

#[derive(Clone, Debug, Serialize)]
pub struct RekeyParitySummary {
    pub matches: bool,
    pub compared_rounds: u64,
    pub compared_inputs: usize,
    pub compared_hashes: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct RebuildSummary {
    pub build: BuildSummary,
    pub run: LoopSummary,
}

#[derive(Clone, Copy, Debug)]
enum SessionMode {
    Light,
    Fast,
}

struct Workload {
    initial_key: Vec<u8>,
    rekey_key: Vec<u8>,
    inputs: Vec<Vec<u8>>,
}

struct BuiltVm {
    vm: RandomXVm,
    build: BuildSummary,
    page_backing: PageBackingSummary,
}

struct HashLoopCapture {
    outputs: Vec<[u8; 32]>,
    summary: LoopSummary,
}

impl Default for HarnessOptions {
    fn default() -> Self {
        Self {
            mode: HarnessModeSelection::Both,
            runtime_profile: RuntimeProfile::supported_default(),
            warmup_rounds: 1,
            steady_rounds: 3,
            threads: std::thread::available_parallelism()
                .map(|value| value.get())
                .unwrap_or(1),
            large_pages: false,
            use_1gb_pages: false,
            calibration: None,
            workload_id: PREFETCH_CALIBRATION_WORKLOAD_ID.to_string(),
            config: RandomXConfig::new(),
        }
    }
}

impl HarnessModeSelection {
    pub fn label(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Fast => "fast",
            Self::Both => "both",
        }
    }
}

impl RuntimeProfile {
    pub fn supported_default() -> Self {
        if cfg!(feature = "jit-fastregs") {
            Self::JitFastRegs
        } else if cfg!(feature = "jit") {
            Self::JitConservative
        } else {
            Self::Interpreter
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Interpreter => "interpreter",
            Self::JitConservative => "jit-conservative",
            Self::JitFastRegs => "jit-fastregs",
        }
    }
}

impl SessionMode {
    fn label(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Fast => "fast",
        }
    }

    fn calibration_mode(self) -> PrefetchCalibrationMode {
        match self {
            Self::Light => PrefetchCalibrationMode::Light,
            Self::Fast => PrefetchCalibrationMode::Fast,
        }
    }
}

impl FlagSummary {
    fn from_flags(flags: &RandomXFlags) -> Self {
        Self {
            prefetch: flags.prefetch,
            prefetch_distance: flags.prefetch_distance,
            prefetch_auto_tune: flags.prefetch_auto_tune,
            scratchpad_prefetch_distance: flags.scratchpad_prefetch_distance,
            large_pages: flags.large_pages_plumbing,
            use_1gb_pages: flags.use_1gb_pages,
            jit_requested: flags_jit_requested(flags),
            jit_fast_regs_requested: flags_jit_fast_regs_requested(flags),
        }
    }
}

impl BuildContractSummary {
    fn current() -> Self {
        Self {
            production_features: PRODUCTION_FEATURES,
            validation_features: VALIDATION_FEATURES,
            supported_runtime_profiles: SUPPORTED_RUNTIME_PROFILES,
            compiled_features: CompiledFeatureSummary::current(),
        }
    }
}

impl CompiledFeatureSummary {
    fn current() -> Self {
        Self {
            jit: cfg!(feature = "jit"),
            jit_fastregs: cfg!(feature = "jit-fastregs"),
            bench_instrument: cfg!(feature = "bench-instrument"),
        }
    }
}

impl TelemetrySummary {
    fn from_perf(perf: PerfStats) -> Self {
        Self {
            instrumented: cfg!(feature = "bench-instrument"),
            hashes: perf.hashes,
            program_execs: perf.program_execs,
            program_gen_ns: perf.program_gen_ns,
            prepare_iteration_ns: perf.prepare_iteration_ns,
            execute_program_ns_interpreter: perf.vm_exec_ns_interpreter,
            execute_program_ns_jit: perf.vm_exec_ns_jit,
            finish_iteration_ns: perf.finish_iteration_ns,
            dataset_item_loads: perf.dataset_item_loads,
            scratchpad_read_bytes: perf.scratchpad_read_bytes,
            scratchpad_write_bytes: perf.scratchpad_write_bytes,
            jit_fastregs_prepare_ns: perf.jit_fastregs_prepare_ns,
            jit_fastregs_finish_ns: perf.jit_fastregs_finish_ns,
        }
    }
}

pub fn run_validation_harness(opts: &HarnessOptions) -> Result<HarnessReport, String> {
    validate_options(opts)?;

    let requested_flags = build_requested_flags(opts)?;
    let workload = workload();
    let sessions = match opts.mode {
        HarnessModeSelection::Light => vec![run_session(
            SessionMode::Light,
            opts,
            &requested_flags,
            &workload,
        )?],
        HarnessModeSelection::Fast => vec![run_session(
            SessionMode::Fast,
            opts,
            &requested_flags,
            &workload,
        )?],
        HarnessModeSelection::Both => vec![
            run_session(SessionMode::Light, opts, &requested_flags, &workload)?,
            run_session(SessionMode::Fast, opts, &requested_flags, &workload)?,
        ],
    };

    Ok(HarnessReport {
        report_version: REPORT_VERSION,
        purpose: PURPOSE,
        build_contract: BuildContractSummary::current(),
        requested_mode: opts.mode.label().to_string(),
        requested_runtime_profile: opts.runtime_profile.label().to_string(),
        warmup_rounds: opts.warmup_rounds,
        steady_rounds: opts.steady_rounds,
        threads: opts.threads,
        instrumented: cfg!(feature = "bench-instrument"),
        workload_id: opts.workload_id.clone(),
        calibration_path: opts
            .calibration
            .as_ref()
            .map(|path| path.display().to_string()),
        requested_flags: FlagSummary::from_flags(&requested_flags),
        sessions,
    })
}

pub fn format_report_human(report: &HarnessReport) -> String {
    let mut out = String::new();
    out.push_str("oxide-randomx integration harness\n");
    out.push_str(&format!(
        "report_version={} purpose=validate supported OxideMiner lifecycle; not a benchmark\n",
        report.report_version
    ));
    out.push_str(&format!(
        "build_contract production_features=\"{}\" validation_features=\"{}\" supported_runtime_profiles={} compiled_features={}\n",
        report.build_contract.production_features,
        report.build_contract.validation_features,
        format_supported_runtime_profiles(&report.build_contract.supported_runtime_profiles),
        format_compiled_features(&report.build_contract.compiled_features),
    ));
    out.push_str(&format!(
        "requested_mode={} requested_runtime_profile={} warmup_rounds={} steady_rounds={} threads={} instrumented={} workload_id={} calibration_path={}\n",
        report.requested_mode,
        report.requested_runtime_profile,
        report.warmup_rounds,
        report.steady_rounds,
        report.threads,
        report.instrumented,
        report.workload_id,
        report.calibration_path.as_deref().unwrap_or("none"),
    ));
    out.push_str(&format!(
        "requested_flags {}\n",
        format_flags(&report.requested_flags)
    ));

    for session in &report.sessions {
        out.push_str(&format!("\nmode={}\n", session.mode));
        out.push_str(&format!(
            "  lifecycle requested_runtime_profile={} effective_runtime_profile={} fallback_reason={} rekey_matches_rebuild={}\n",
            session.lifecycle.requested_runtime_profile,
            session.lifecycle.effective_runtime_profile,
            session.lifecycle.fallback_reason.as_deref().unwrap_or("none"),
            session.lifecycle.rekey_matches_rebuild,
        ));
        out.push_str(&format!(
            "  jit {}\n",
            format_jit_summary(&session.lifecycle.jit)
        ));
        out.push_str(&format!(
            "  calibration requested={} status={} path={}\n",
            session.calibration.requested,
            session.calibration.status,
            session.calibration.path.as_deref().unwrap_or("none")
        ));
        if let Some(distance) = session.calibration.matched_best_prefetch_distance {
            out.push_str(&format!(
                "  calibration_match best_prefetch_distance={} best_ns_per_hash={} cpu={} workload_id={}\n",
                distance,
                session
                    .calibration
                    .matched_best_ns_per_hash
                    .unwrap_or_default(),
                session
                    .calibration
                    .matched_cpu
                    .as_deref()
                    .unwrap_or("unknown"),
                session
                    .calibration
                    .matched_workload_id
                    .as_deref()
                    .unwrap_or("unknown"),
            ));
        }
        out.push_str(&format!(
            "  requested_flags {}\n",
            format_flags(&session.requested_flags)
        ));
        out.push_str(&format!(
            "  effective_flags {}\n",
            format_flags(&session.effective_flags)
        ));
        out.push_str(&format!(
            "  build cache_init_ns={} dataset_init_ns={} vm_init_ns={} jit_active={}\n",
            session.build.cache_init_ns,
            option_ns(session.build.dataset_init_ns),
            session.build.vm_init_ns,
            session.build.jit_active,
        ));
        out.push_str(&format!(
            "  page_request scratchpad {}\n",
            format_page_request(&session.page_backing.scratchpad)
        ));
        out.push_str(&format!(
            "  page_realized scratchpad {}\n",
            format_realized_page_backing(&session.page_backing.scratchpad)
        ));
        if let Some(dataset) = session.page_backing.dataset.as_ref() {
            out.push_str(&format!(
                "  page_request dataset {}\n",
                format_page_request(dataset)
            ));
            out.push_str(&format!(
                "  page_realized dataset {}\n",
                format_realized_page_backing(dataset)
            ));
        } else {
            out.push_str("  page_request dataset not_applicable_in_light_mode\n");
            out.push_str("  page_realized dataset not_applicable_in_light_mode\n");
        }
        out.push_str(&format!(
            "  steady_state rounds={} hashes={} elapsed_ns={} xor={} first={} last={}\n",
            session.steady_state.rounds,
            session.steady_state.total_hashes,
            session.steady_state.elapsed_ns,
            session.steady_state.output_xor_hex,
            session.steady_state.first_hash_hex,
            session.steady_state.last_hash_hex,
        ));
        if session.telemetry.instrumented {
            out.push_str(&format!(
                "  telemetry hashes={} program_execs={} program_gen_ns={} prepare_iteration_ns={} execute_interp_ns={} execute_jit_ns={} finish_iteration_ns={} dataset_item_loads={} scratchpad_read_bytes={} scratchpad_write_bytes={} jit_fastregs_prepare_ns={} jit_fastregs_finish_ns={}\n",
                session.telemetry.hashes,
                session.telemetry.program_execs,
                session.telemetry.program_gen_ns,
                session.telemetry.prepare_iteration_ns,
                session.telemetry.execute_program_ns_interpreter,
                session.telemetry.execute_program_ns_jit,
                session.telemetry.finish_iteration_ns,
                session.telemetry.dataset_item_loads,
                session.telemetry.scratchpad_read_bytes,
                session.telemetry.scratchpad_write_bytes,
                session.telemetry.jit_fastregs_prepare_ns,
                session.telemetry.jit_fastregs_finish_ns,
            ));
        } else {
            out.push_str(
                "  telemetry instrumented=false (PerfStats are zero without --features bench-instrument)\n",
            );
        }
        out.push_str(&format!(
            "  rekey rekey_elapsed_ns={} parity_matches={} compared_rounds={} compared_inputs={} compared_hashes={}\n",
            session.rekey.rekey_elapsed_ns,
            session.rekey.parity.matches,
            session.rekey.parity.compared_rounds,
            session.rekey.parity.compared_inputs,
            session.rekey.parity.compared_hashes,
        ));
        out.push_str(&format!(
            "  rekey_in_place hashes={} elapsed_ns={} xor={} first={} last={}\n",
            session.rekey.in_place.total_hashes,
            session.rekey.in_place.elapsed_ns,
            session.rekey.in_place.output_xor_hex,
            session.rekey.in_place.first_hash_hex,
            session.rekey.in_place.last_hash_hex,
        ));
        out.push_str(&format!(
            "  rekey_rebuild cache_init_ns={} dataset_init_ns={} vm_init_ns={} hashes={} elapsed_ns={} xor={} first={} last={}\n",
            session.rekey.rebuild.build.cache_init_ns,
            option_ns(session.rekey.rebuild.build.dataset_init_ns),
            session.rekey.rebuild.build.vm_init_ns,
            session.rekey.rebuild.run.total_hashes,
            session.rekey.rebuild.run.elapsed_ns,
            session.rekey.rebuild.run.output_xor_hex,
            session.rekey.rebuild.run.first_hash_hex,
            session.rekey.rebuild.run.last_hash_hex,
        ));
    }

    out
}

pub fn format_report_json(report: &HarnessReport) -> String {
    serde_json::to_string_pretty(report).expect("serialize integration report")
}

fn validate_options(opts: &HarnessOptions) -> Result<(), String> {
    if opts.steady_rounds == 0 {
        return Err("steady_rounds must be greater than zero".to_string());
    }
    if opts.threads == 0 {
        return Err("threads must be greater than zero".to_string());
    }
    Ok(())
}

fn run_session(
    mode: SessionMode,
    opts: &HarnessOptions,
    requested_flags: &RandomXFlags,
    workload: &Workload,
) -> Result<SessionReport, String> {
    let cfg = opts.config.clone();
    let mut effective_flags = requested_flags.clone();
    let calibration = apply_calibration(
        mode,
        &mut effective_flags,
        opts.calibration.as_deref(),
        &opts.workload_id,
    )?;
    let BuiltVm {
        mut vm,
        build,
        page_backing,
    } = build_vm(
        mode,
        &cfg,
        &effective_flags,
        workload.initial_key.as_slice(),
        opts.threads,
    )?;

    warmup_hashes(&mut vm, &workload.inputs, opts.warmup_rounds);
    vm.reset_perf_stats();
    let steady_state = run_hash_loop(&mut vm, &workload.inputs, opts.steady_rounds).summary;
    let telemetry = TelemetrySummary::from_perf(vm.perf_stats());
    let rekey = run_rekey_flow(
        mode,
        &cfg,
        &effective_flags,
        opts.threads,
        &workload.inputs,
        workload.rekey_key.as_slice(),
        &mut vm,
    )?;
    let effective_runtime_profile =
        effective_runtime_profile(opts.runtime_profile, build.jit_active);
    let lifecycle = LifecycleSummary {
        requested_runtime_profile: opts.runtime_profile.label().to_string(),
        effective_runtime_profile: effective_runtime_profile.label().to_string(),
        fallback_reason: runtime_fallback_reason(opts.runtime_profile, effective_runtime_profile),
        jit: JitSummary {
            requested: flags_jit_requested(requested_flags),
            requested_fast_regs: flags_jit_fast_regs_requested(requested_flags),
            compiled_jit_support: cfg!(feature = "jit"),
            compiled_fast_regs_support: cfg!(feature = "jit-fastregs"),
            active: build.jit_active,
        },
        rekey_matches_rebuild: rekey.parity.matches,
    };

    Ok(SessionReport {
        mode: mode.label().to_string(),
        lifecycle,
        calibration,
        requested_flags: FlagSummary::from_flags(requested_flags),
        effective_flags: FlagSummary::from_flags(&effective_flags),
        build,
        page_backing,
        steady_state,
        telemetry,
        rekey,
    })
}

fn build_requested_flags(opts: &HarnessOptions) -> Result<RandomXFlags, String> {
    let mut flags = RandomXFlags::from_env();
    flags.large_pages_plumbing = opts.large_pages || opts.use_1gb_pages;
    flags.use_1gb_pages = opts.use_1gb_pages;

    #[cfg(feature = "jit")]
    {
        match opts.runtime_profile {
            RuntimeProfile::Interpreter => {
                flags.jit = false;
                flags.jit_fast_regs = false;
            }
            RuntimeProfile::JitConservative => {
                flags.jit = true;
                flags.jit_fast_regs = false;
            }
            RuntimeProfile::JitFastRegs => {
                if !cfg!(feature = "jit-fastregs") {
                    return Err(
                        "jit-fastregs runtime profile requires compiling with --features \"jit jit-fastregs\""
                            .to_string(),
                    );
                }
                flags.jit = true;
                flags.jit_fast_regs = true;
            }
        }
    }
    #[cfg(not(feature = "jit"))]
    {
        if !matches!(opts.runtime_profile, RuntimeProfile::Interpreter) {
            return Err("JIT runtime profiles require compiling with --features jit".to_string());
        }
    }

    Ok(flags)
}

fn apply_calibration(
    mode: SessionMode,
    flags: &mut RandomXFlags,
    calibration: Option<&Path>,
    workload_id: &str,
) -> Result<CalibrationSummary, String> {
    let Some(path) = calibration else {
        return Ok(CalibrationSummary {
            requested: false,
            path: None,
            status: "NotRequested".to_string(),
            matched_best_prefetch_distance: None,
            matched_best_ns_per_hash: None,
            matched_cpu: None,
            matched_workload_id: None,
        });
    };

    let outcome = apply_prefetch_calibration_for_current_host(
        path,
        mode.calibration_mode(),
        flags,
        workload_id,
    )?;

    let (distance, ns_per_hash, cpu, matched_workload_id) = match outcome.record.as_ref() {
        Some(record) => (
            Some(record.best_prefetch_distance),
            Some(record.best_ns_per_hash),
            Some(format!(
                "{}/{}/{}/{} ({})",
                record.cpu.vendor,
                record.cpu.family,
                record.cpu.model,
                record.cpu.stepping,
                record.cpu.family_bucket
            )),
            Some(record.scenario.workload_id.clone()),
        ),
        None => (None, None, None, None),
    };

    Ok(CalibrationSummary {
        requested: true,
        path: Some(path.display().to_string()),
        status: calibration_status_label(outcome.status).to_string(),
        matched_best_prefetch_distance: distance,
        matched_best_ns_per_hash: ns_per_hash,
        matched_cpu: cpu,
        matched_workload_id,
    })
}

fn run_rekey_flow(
    mode: SessionMode,
    cfg: &RandomXConfig,
    flags: &RandomXFlags,
    threads: usize,
    inputs: &[Vec<u8>],
    rekey_key: &[u8],
    vm: &mut RandomXVm,
) -> Result<RekeySummary, String> {
    let rekey_start = Instant::now();
    vm.rekey(rekey_key).map_err(|err| err.to_string())?;
    let rekey_elapsed_ns = rekey_start.elapsed().as_nanos() as u64;
    let in_place = run_hash_loop(vm, inputs, 1);

    let BuiltVm { mut vm, build, .. } = build_vm(mode, cfg, flags, rekey_key, threads)?;
    let rebuild = run_hash_loop(&mut vm, inputs, 1);

    Ok(RekeySummary {
        rekey_elapsed_ns,
        parity: RekeyParitySummary {
            matches: in_place.outputs == rebuild.outputs,
            compared_rounds: rebuild.summary.rounds,
            compared_inputs: rebuild.summary.input_count,
            compared_hashes: rebuild.summary.total_hashes,
        },
        in_place: in_place.summary,
        rebuild: RebuildSummary {
            build,
            run: rebuild.summary,
        },
    })
}

fn build_vm(
    mode: SessionMode,
    cfg: &RandomXConfig,
    flags: &RandomXFlags,
    key: &[u8],
    threads: usize,
) -> Result<BuiltVm, String> {
    let cache_start = Instant::now();
    let cache = RandomXCache::new(key, cfg).map_err(|err| err.to_string())?;
    let cache_init_ns = cache_start.elapsed().as_nanos() as u64;

    match mode {
        SessionMode::Light => {
            let vm_start = Instant::now();
            let vm = RandomXVm::new_light(cache, cfg.clone(), flags.clone())
                .map_err(|err| err.to_string())?;
            let vm_init_ns = vm_start.elapsed().as_nanos() as u64;
            let build = BuildSummary {
                cache_init_ns,
                dataset_init_ns: None,
                vm_init_ns,
                jit_active: vm.is_jit_active(),
            };
            let page_backing = PageBackingSummary {
                scratchpad: page_allocation_summary(
                    "scratchpad",
                    flags.large_pages_plumbing,
                    false,
                    vm.scratchpad_uses_large_pages(),
                    vm.scratchpad_huge_page_size(),
                ),
                dataset: None,
            };
            Ok(BuiltVm {
                vm,
                build,
                page_backing,
            })
        }
        SessionMode::Fast => {
            let dataset_options = DatasetInitOptions::new(threads)
                .with_large_pages(flags.large_pages_plumbing)
                .with_1gb_pages(flags.use_1gb_pages);
            let dataset_start = Instant::now();
            let dataset = RandomXDataset::new_with_options(&cache, cfg, dataset_options)
                .map_err(|err| err.to_string())?;
            let dataset_init_ns = dataset_start.elapsed().as_nanos() as u64;
            let dataset_page_backing = page_allocation_summary(
                "dataset",
                flags.large_pages_plumbing,
                flags.use_1gb_pages,
                dataset.uses_large_pages(),
                dataset.huge_page_size(),
            );
            let vm_start = Instant::now();
            let vm = RandomXVm::new_fast(cache, dataset, cfg.clone(), flags.clone())
                .map_err(|err| err.to_string())?;
            let vm_init_ns = vm_start.elapsed().as_nanos() as u64;
            let build = BuildSummary {
                cache_init_ns,
                dataset_init_ns: Some(dataset_init_ns),
                vm_init_ns,
                jit_active: vm.is_jit_active(),
            };
            let page_backing = PageBackingSummary {
                scratchpad: page_allocation_summary(
                    "scratchpad",
                    flags.large_pages_plumbing,
                    false,
                    vm.scratchpad_uses_large_pages(),
                    vm.scratchpad_huge_page_size(),
                ),
                dataset: Some(dataset_page_backing),
            };
            Ok(BuiltVm {
                vm,
                build,
                page_backing,
            })
        }
    }
}

fn warmup_hashes(vm: &mut RandomXVm, inputs: &[Vec<u8>], rounds: u64) {
    for _ in 0..rounds {
        for input in inputs {
            let _ = vm.hash(input);
        }
    }
}

fn run_hash_loop(vm: &mut RandomXVm, inputs: &[Vec<u8>], rounds: u64) -> HashLoopCapture {
    let mut outputs = Vec::with_capacity((rounds as usize).saturating_mul(inputs.len()));
    let mut output_xor = [0u8; 32];
    let mut first_hash = None;
    let mut last_hash = [0u8; 32];
    let start = Instant::now();

    for _ in 0..rounds {
        for input in inputs {
            let hash = vm.hash(input);
            if first_hash.is_none() {
                first_hash = Some(hash);
            }
            for (slot, byte) in output_xor.iter_mut().zip(hash.iter()) {
                *slot ^= *byte;
            }
            last_hash = hash;
            outputs.push(hash);
        }
    }

    let elapsed_ns = start.elapsed().as_nanos() as u64;
    let first_hash = first_hash.unwrap_or([0u8; 32]);
    HashLoopCapture {
        outputs,
        summary: LoopSummary {
            rounds,
            input_count: inputs.len(),
            total_hashes: rounds.saturating_mul(inputs.len() as u64),
            elapsed_ns,
            first_hash_hex: bytes_to_hex(&first_hash),
            last_hash_hex: bytes_to_hex(&last_hash),
            output_xor_hex: bytes_to_hex(&output_xor),
        },
    }
}

fn workload() -> Workload {
    let mut initial_key = vec![0u8; 32];
    for (idx, byte) in initial_key.iter_mut().enumerate() {
        *byte = idx as u8;
    }

    let mut rekey_key = vec![0u8; 32];
    for (idx, byte) in rekey_key.iter_mut().enumerate() {
        *byte = 0xA5u8 ^ ((idx as u8).wrapping_mul(11));
    }

    let sizes = [0usize, 1, 16, 64, 256, 1024];
    let mut inputs = Vec::with_capacity(sizes.len());
    let mut state = 0x243f_6a88_85a3_08d3u64;
    for size in sizes {
        let mut input = Vec::with_capacity(size);
        for _ in 0..size {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            input.push((state >> 56) as u8);
        }
        inputs.push(input);
    }

    Workload {
        initial_key,
        rekey_key,
        inputs,
    }
}

fn effective_runtime_profile(requested: RuntimeProfile, jit_active: bool) -> RuntimeProfile {
    if !jit_active {
        RuntimeProfile::Interpreter
    } else {
        requested
    }
}

fn runtime_fallback_reason(requested: RuntimeProfile, effective: RuntimeProfile) -> Option<String> {
    if requested == effective {
        None
    } else {
        Some("jit_requested_but_not_active".to_string())
    }
}

fn page_allocation_summary(
    allocation: &str,
    requested_large_pages: bool,
    requested_1gb_pages: bool,
    realized_large_pages: bool,
    realized_huge_page_size: Option<usize>,
) -> PageAllocationSummary {
    PageAllocationSummary {
        allocation: allocation.to_string(),
        request: PageRequestSummary {
            large_pages: requested_large_pages,
            use_1gb_pages: requested_1gb_pages,
        },
        realized: RealizedPageBackingSummary {
            large_pages: realized_large_pages,
            huge_page_size: realized_huge_page_size,
            description: page_size_description(realized_huge_page_size).to_string(),
        },
        realization: page_realization_label(
            requested_large_pages,
            requested_1gb_pages,
            realized_large_pages,
            realized_huge_page_size,
        )
        .to_string(),
    }
}

fn page_realization_label(
    requested_large_pages: bool,
    requested_1gb_pages: bool,
    realized_large_pages: bool,
    realized_huge_page_size: Option<usize>,
) -> &'static str {
    let realized_1gb = matches!(realized_huge_page_size, Some(size) if size >= 1024 * 1024 * 1024);
    let realized_2mb = matches!(realized_huge_page_size, Some(size) if size >= 2 * 1024 * 1024);

    match (
        requested_large_pages,
        requested_1gb_pages,
        realized_large_pages,
        realized_1gb,
        realized_2mb,
    ) {
        (false, false, false, _, _) => "not_requested",
        (false, false, true, true, _) => "realized_without_request_1gb",
        (false, false, true, false, true) => "realized_without_request_2mb",
        (false, false, true, false, false) => "realized_without_request_large_pages",
        (true, false, false, _, _) => "requested_fallback_standard_4kb",
        (true, false, true, true, _) => "realized_1gb_large_pages",
        (true, false, true, false, true) => "realized_2mb_large_pages",
        (true, false, true, false, false) => "realized_large_pages",
        (true, true, false, _, _) => "requested_1gb_fallback_standard_4kb",
        (true, true, true, true, _) => "realized_1gb_large_pages",
        (true, true, true, false, true) => "requested_1gb_fallback_2mb_large_pages",
        (true, true, true, false, false) => "requested_1gb_realized_nonstandard_large_pages",
        (false, true, false, _, _) => "requested_1gb_without_large_pages_fallback_standard_4kb",
        (false, true, true, true, _) => "requested_1gb_without_large_pages_realized_1gb",
        (false, true, true, false, true) => "requested_1gb_without_large_pages_fallback_2mb",
        (false, true, true, false, false) => {
            "requested_1gb_without_large_pages_realized_nonstandard_large_pages"
        }
    }
}

fn calibration_status_label(status: PrefetchCalibrationApplyStatus) -> &'static str {
    match status {
        PrefetchCalibrationApplyStatus::Applied => "Applied",
        PrefetchCalibrationApplyStatus::NoCalibrationFile => "NoCalibrationFile",
        PrefetchCalibrationApplyStatus::NoMatchingCalibration => "NoMatchingCalibration",
    }
}

fn page_size_description(huge_page_size: Option<usize>) -> &'static str {
    match huge_page_size {
        Some(size) if size >= 1024 * 1024 * 1024 => "1GB huge pages",
        Some(size) if size >= 2 * 1024 * 1024 => "2MB huge pages",
        Some(_) => "large pages",
        None => "standard 4KB pages",
    }
}

fn format_flags(flags: &FlagSummary) -> String {
    format!(
        "prefetch={} prefetch_distance={} prefetch_auto_tune={} scratchpad_prefetch_distance={} large_pages={} use_1gb_pages={} jit_requested={} jit_fast_regs_requested={}",
        flags.prefetch,
        flags.prefetch_distance,
        flags.prefetch_auto_tune,
        flags.scratchpad_prefetch_distance,
        flags.large_pages,
        flags.use_1gb_pages,
        flags.jit_requested,
        flags.jit_fast_regs_requested,
    )
}

fn format_compiled_features(features: &CompiledFeatureSummary) -> String {
    format!(
        "jit={} jit_fastregs={} bench_instrument={}",
        features.jit, features.jit_fastregs, features.bench_instrument
    )
}

fn format_supported_runtime_profiles(profiles: &[&str]) -> String {
    profiles.join(",")
}

fn format_jit_summary(summary: &JitSummary) -> String {
    format!(
        "requested={} requested_fast_regs={} compiled_jit_support={} compiled_fast_regs_support={} active={}",
        summary.requested,
        summary.requested_fast_regs,
        summary.compiled_jit_support,
        summary.compiled_fast_regs_support,
        summary.active,
    )
}

fn format_page_request(summary: &PageAllocationSummary) -> String {
    format!(
        "allocation={} large_pages={} use_1gb_pages={}",
        summary.allocation, summary.request.large_pages, summary.request.use_1gb_pages,
    )
}

fn format_realized_page_backing(summary: &PageAllocationSummary) -> String {
    format!(
        "allocation={} large_pages={} huge_page_size={} realization={} description={}",
        summary.allocation,
        summary.realized.large_pages,
        option_usize(summary.realized.huge_page_size),
        summary.realization,
        summary.realized.description,
    )
}

fn option_ns(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "n/a".to_string())
}

fn option_usize(value: Option<usize>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "n/a".to_string())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(LUT[(byte >> 4) as usize] as char);
        out.push(LUT[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(feature = "jit")]
fn flags_jit_requested(flags: &RandomXFlags) -> bool {
    flags.jit
}

#[cfg(not(feature = "jit"))]
fn flags_jit_requested(_flags: &RandomXFlags) -> bool {
    false
}

#[cfg(feature = "jit")]
fn flags_jit_fast_regs_requested(flags: &RandomXFlags) -> bool {
    flags.jit_fast_regs
}

#[cfg(not(feature = "jit"))]
fn flags_jit_fast_regs_requested(_flags: &RandomXFlags) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_realization_distinguishes_1gb_fallback() {
        assert_eq!(
            page_realization_label(true, true, true, Some(2 * 1024 * 1024)),
            "requested_1gb_fallback_2mb_large_pages"
        );
        assert_eq!(
            page_realization_label(true, false, false, None),
            "requested_fallback_standard_4kb"
        );
        assert_eq!(
            page_realization_label(false, false, false, None),
            "not_requested"
        );
    }

    #[test]
    fn default_runtime_profile_tracks_build_capability() {
        let expected = if cfg!(feature = "jit-fastregs") {
            RuntimeProfile::JitFastRegs
        } else if cfg!(feature = "jit") {
            RuntimeProfile::JitConservative
        } else {
            RuntimeProfile::Interpreter
        };
        assert_eq!(RuntimeProfile::supported_default(), expected);
    }
}
