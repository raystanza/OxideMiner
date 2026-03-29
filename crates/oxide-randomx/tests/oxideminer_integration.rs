use oxide_randomx::{
    oxideminer_integration::{
        format_report_human, format_report_json, run_validation_harness, HarnessModeSelection,
        HarnessOptions, RuntimeProfile, PRODUCTION_FEATURES, REPORT_VERSION,
        SUPPORTED_RUNTIME_PROFILES, VALIDATION_FEATURES,
    },
    DatasetInitOptions, RandomXCache, RandomXConfig, RandomXDataset, RandomXFlags, RandomXVm,
};
use serde_json::Value;

#[test]
fn light_public_rekey_matches_full_rebuild() {
    let cfg = RandomXConfig::test_small();
    let flags = RandomXFlags::default();
    let inputs = workload_inputs();
    let initial_key = initial_key();
    let rekey_key = rekey_key();

    let cache = RandomXCache::new(&initial_key, &cfg).expect("cache");
    let mut vm = RandomXVm::new_light(cache, cfg.clone(), flags.clone()).expect("vm");
    let _ = collect_hashes(&mut vm, &inputs, 2);

    vm.rekey(&rekey_key).expect("rekey");
    let rekeyed = collect_hashes(&mut vm, &inputs, 1);

    let rebuilt_cache = RandomXCache::new(&rekey_key, &cfg).expect("cache");
    let mut rebuilt = RandomXVm::new_light(rebuilt_cache, cfg, flags).expect("vm");
    let rebuilt_hashes = collect_hashes(&mut rebuilt, &inputs, 1);

    assert_eq!(rekeyed, rebuilt_hashes);
}

#[test]
fn fast_public_rekey_matches_full_rebuild() {
    let cfg = RandomXConfig::test_small();
    let flags = RandomXFlags::default();
    let inputs = workload_inputs();
    let initial_key = initial_key();
    let rekey_key = rekey_key();

    let cache = RandomXCache::new(&initial_key, &cfg).expect("cache");
    let dataset = RandomXDataset::new_with_options(
        &cache,
        &cfg,
        DatasetInitOptions::new(1).with_large_pages(false),
    )
    .expect("dataset");
    let mut vm = RandomXVm::new_fast(cache, dataset, cfg.clone(), flags.clone()).expect("vm");
    let _ = collect_hashes(&mut vm, &inputs, 2);

    vm.rekey(&rekey_key).expect("rekey");
    let rekeyed = collect_hashes(&mut vm, &inputs, 1);

    let rebuilt_cache = RandomXCache::new(&rekey_key, &cfg).expect("cache");
    let rebuilt_dataset = RandomXDataset::new_with_options(
        &rebuilt_cache,
        &cfg,
        DatasetInitOptions::new(1).with_large_pages(false),
    )
    .expect("dataset");
    let mut rebuilt = RandomXVm::new_fast(rebuilt_cache, rebuilt_dataset, cfg, flags).expect("vm");
    let rebuilt_hashes = collect_hashes(&mut rebuilt, &inputs, 1);

    assert_eq!(rekeyed, rebuilt_hashes);
}

#[test]
fn public_harness_report_tracks_requested_and_effective_profiles() {
    let report = run_validation_harness(&base_opts(
        HarnessModeSelection::Light,
        RuntimeProfile::Interpreter,
    ))
    .expect("report");

    assert_eq!(report.report_version, REPORT_VERSION);
    assert_eq!(
        report.build_contract.production_features,
        PRODUCTION_FEATURES
    );
    assert_eq!(
        report.build_contract.validation_features,
        VALIDATION_FEATURES
    );
    assert_eq!(
        report.build_contract.supported_runtime_profiles,
        SUPPORTED_RUNTIME_PROFILES
    );
    assert_eq!(report.requested_runtime_profile, "interpreter");
    assert_eq!(report.sessions.len(), 1);

    let session = &report.sessions[0];
    assert_eq!(session.lifecycle.requested_runtime_profile, "interpreter");
    assert_eq!(session.lifecycle.effective_runtime_profile, "interpreter");
    assert!(session.lifecycle.fallback_reason.is_none());
    assert!(!session.lifecycle.jit.requested);
    assert!(!session.lifecycle.jit.requested_fast_regs);
    assert_eq!(
        session.lifecycle.jit.compiled_jit_support,
        cfg!(feature = "jit")
    );
    assert_eq!(
        session.lifecycle.jit.compiled_fast_regs_support,
        cfg!(feature = "jit-fastregs")
    );
    assert!(!session.lifecycle.jit.active);
    assert_eq!(
        session.requested_flags.jit_requested,
        report.requested_flags.jit_requested
    );
    assert_eq!(
        session.requested_flags.jit_fast_regs_requested,
        report.requested_flags.jit_fast_regs_requested
    );
    assert!(session.lifecycle.rekey_matches_rebuild);
    assert!(session.rekey.parity.matches);
    assert_eq!(session.rekey.parity.compared_rounds, 1);
}

#[test]
fn public_harness_output_exposes_page_backing_contract() {
    let report = run_validation_harness(&base_opts(
        HarnessModeSelection::Fast,
        RuntimeProfile::Interpreter,
    ))
    .expect("report");
    let session = &report.sessions[0];
    let dataset = session
        .page_backing
        .dataset
        .as_ref()
        .expect("fast mode dataset summary");

    assert!(!dataset.request.large_pages);
    assert!(!dataset.request.use_1gb_pages);
    assert_eq!(dataset.realization, "not_requested");
    assert!(!dataset.realized.large_pages);
    assert!(dataset.realized.huge_page_size.is_none());
    assert_eq!(dataset.realized.description, "standard 4KB pages");
    assert!(!session.page_backing.scratchpad.request.large_pages);
    assert_eq!(session.page_backing.scratchpad.realization, "not_requested");

    let human = format_report_human(&report);
    assert!(human.contains("report_version=oxideminer-integration-v2"));
    assert!(human.contains("page_request dataset"));
    assert!(human.contains("page_realized dataset"));
    assert!(human.contains("realization=not_requested"));

    let parsed = report_json(&report);
    assert_eq!(parsed["report_version"], REPORT_VERSION);
    assert_eq!(
        parsed["sessions"][0]["page_backing"]["dataset"]["request"]["large_pages"],
        false
    );
    assert_eq!(
        parsed["sessions"][0]["page_backing"]["dataset"]["realization"],
        "not_requested"
    );
}

#[test]
fn public_harness_scopes_1gb_request_to_the_fast_dataset() {
    let mut opts = base_opts(HarnessModeSelection::Fast, RuntimeProfile::Interpreter);
    opts.use_1gb_pages = true;

    let report = run_validation_harness(&opts).expect("report");
    let session = &report.sessions[0];
    let dataset = session
        .page_backing
        .dataset
        .as_ref()
        .expect("fast mode dataset summary");

    assert!(report.requested_flags.large_pages);
    assert!(report.requested_flags.use_1gb_pages);
    assert!(session.requested_flags.large_pages);
    assert!(session.requested_flags.use_1gb_pages);
    assert!(session.page_backing.scratchpad.request.large_pages);
    assert!(!session.page_backing.scratchpad.request.use_1gb_pages);
    assert!(dataset.request.large_pages);
    assert!(dataset.request.use_1gb_pages);
    assert!(matches!(
        dataset.realization.as_str(),
        "requested_1gb_fallback_standard_4kb"
            | "requested_1gb_fallback_2mb_large_pages"
            | "requested_1gb_realized_nonstandard_large_pages"
            | "realized_1gb_large_pages"
    ));

    let parsed = report_json(&report);
    assert_eq!(
        parsed["sessions"][0]["page_backing"]["scratchpad"]["request"]["use_1gb_pages"],
        false
    );
    assert_eq!(
        parsed["sessions"][0]["page_backing"]["dataset"]["request"]["use_1gb_pages"],
        true
    );
}

#[test]
fn public_harness_json_schema_is_stable() {
    let report = run_validation_harness(&base_opts(
        HarnessModeSelection::Fast,
        RuntimeProfile::Interpreter,
    ))
    .expect("report");
    let parsed = report_json(&report);
    let root = parsed.as_object().expect("report object");

    assert_has_keys(
        root,
        &[
            "build_contract",
            "calibration_path",
            "instrumented",
            "purpose",
            "report_version",
            "requested_flags",
            "requested_mode",
            "requested_runtime_profile",
            "sessions",
            "steady_rounds",
            "threads",
            "warmup_rounds",
            "workload_id",
        ],
    );
    assert_has_keys(
        parsed["build_contract"]
            .as_object()
            .expect("build_contract"),
        &[
            "compiled_features",
            "production_features",
            "supported_runtime_profiles",
            "validation_features",
        ],
    );
    assert_has_keys(
        parsed["build_contract"]["compiled_features"]
            .as_object()
            .expect("compiled_features"),
        &["bench_instrument", "jit", "jit_fastregs"],
    );
    assert_has_keys(
        parsed["sessions"][0].as_object().expect("session"),
        &[
            "build",
            "calibration",
            "effective_flags",
            "lifecycle",
            "mode",
            "page_backing",
            "rekey",
            "requested_flags",
            "steady_state",
            "telemetry",
        ],
    );
    assert_has_keys(
        parsed["sessions"][0]["lifecycle"]
            .as_object()
            .expect("lifecycle"),
        &[
            "effective_runtime_profile",
            "fallback_reason",
            "jit",
            "rekey_matches_rebuild",
            "requested_runtime_profile",
        ],
    );
    assert_has_keys(
        parsed["sessions"][0]["lifecycle"]["jit"]
            .as_object()
            .expect("jit"),
        &[
            "active",
            "compiled_fast_regs_support",
            "compiled_jit_support",
            "requested",
            "requested_fast_regs",
        ],
    );
    assert_has_keys(
        parsed["sessions"][0]["page_backing"]["scratchpad"]
            .as_object()
            .expect("scratchpad"),
        &["allocation", "realization", "realized", "request"],
    );
    assert_has_keys(
        parsed["sessions"][0]["page_backing"]["scratchpad"]["request"]
            .as_object()
            .expect("page request"),
        &["large_pages", "use_1gb_pages"],
    );
    assert_has_keys(
        parsed["sessions"][0]["page_backing"]["scratchpad"]["realized"]
            .as_object()
            .expect("page realization"),
        &["description", "huge_page_size", "large_pages"],
    );
    assert_has_keys(
        parsed["sessions"][0]["rekey"].as_object().expect("rekey"),
        &["in_place", "parity", "rebuild", "rekey_elapsed_ns"],
    );
    assert_has_keys(
        parsed["sessions"][0]["rekey"]["parity"]
            .as_object()
            .expect("parity"),
        &[
            "compared_hashes",
            "compared_inputs",
            "compared_rounds",
            "matches",
        ],
    );
}

#[cfg(feature = "bench-instrument")]
#[test]
fn public_harness_extracts_telemetry_stably() {
    let mut opts = base_opts(HarnessModeSelection::Light, RuntimeProfile::Interpreter);
    opts.steady_rounds = 2;

    let report = run_validation_harness(&opts).expect("report");
    let session = &report.sessions[0];

    assert!(report.instrumented);
    assert!(session.telemetry.instrumented);
    assert_eq!(session.telemetry.hashes, session.steady_state.total_hashes);
    assert!(session.telemetry.program_execs > 0);
    assert!(session.telemetry.program_gen_ns > 0);
    assert!(session.telemetry.prepare_iteration_ns > 0);
    assert!(session.telemetry.finish_iteration_ns > 0);

    let parsed = report_json(&report);
    assert_eq!(parsed["sessions"][0]["telemetry"]["instrumented"], true);
    assert_eq!(
        parsed["sessions"][0]["telemetry"]["hashes"],
        session.steady_state.total_hashes
    );
}

#[cfg(all(feature = "jit", feature = "jit-fastregs"))]
#[test]
fn public_harness_records_supported_jit_fastregs_request() {
    let report = run_validation_harness(&base_opts(
        HarnessModeSelection::Light,
        RuntimeProfile::JitFastRegs,
    ))
    .expect("report");
    let session = &report.sessions[0];

    assert_eq!(report.requested_runtime_profile, "jit-fastregs");
    assert_eq!(session.lifecycle.requested_runtime_profile, "jit-fastregs");
    assert!(session.requested_flags.jit_requested);
    assert!(session.requested_flags.jit_fast_regs_requested);
    assert!(session.lifecycle.jit.requested);
    assert!(session.lifecycle.jit.requested_fast_regs);
    assert!(session.lifecycle.jit.compiled_jit_support);
    assert!(session.lifecycle.jit.compiled_fast_regs_support);

    if session.lifecycle.jit.active {
        assert_eq!(session.lifecycle.effective_runtime_profile, "jit-fastregs");
        assert!(session.lifecycle.fallback_reason.is_none());
    } else {
        assert_eq!(session.lifecycle.effective_runtime_profile, "interpreter");
        assert_eq!(
            session.lifecycle.fallback_reason.as_deref(),
            Some("jit_requested_but_not_active")
        );
    }
}

fn collect_hashes(vm: &mut RandomXVm, inputs: &[Vec<u8>], rounds: u64) -> Vec<[u8; 32]> {
    let mut outputs = Vec::with_capacity((rounds as usize).saturating_mul(inputs.len()));
    for _ in 0..rounds {
        for input in inputs {
            outputs.push(vm.hash(input));
        }
    }
    outputs
}

fn base_opts(mode: HarnessModeSelection, runtime_profile: RuntimeProfile) -> HarnessOptions {
    let mut opts = HarnessOptions::default();
    opts.config = RandomXConfig::test_small();
    opts.mode = mode;
    opts.runtime_profile = runtime_profile;
    opts.warmup_rounds = 0;
    opts.steady_rounds = 1;
    opts.threads = 1;
    opts.large_pages = false;
    opts.use_1gb_pages = false;
    opts
}

fn report_json(report: &oxide_randomx::oxideminer_integration::HarnessReport) -> Value {
    serde_json::from_str(&format_report_json(report)).expect("json")
}

fn assert_has_keys(object: &serde_json::Map<String, Value>, expected: &[&str]) {
    for key in expected {
        assert!(object.contains_key(*key), "missing key {key}");
    }
    assert_eq!(object.len(), expected.len(), "unexpected key count");
}

fn initial_key() -> Vec<u8> {
    let mut key = vec![0u8; 32];
    for (idx, byte) in key.iter_mut().enumerate() {
        *byte = idx as u8;
    }
    key
}

fn rekey_key() -> Vec<u8> {
    let mut key = vec![0u8; 32];
    for (idx, byte) in key.iter_mut().enumerate() {
        *byte = 0xA5u8 ^ ((idx as u8).wrapping_mul(11));
    }
    key
}

fn workload_inputs() -> Vec<Vec<u8>> {
    let sizes = [0usize, 1, 16, 64];
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
    inputs
}
