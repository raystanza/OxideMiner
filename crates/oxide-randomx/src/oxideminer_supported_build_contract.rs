use crate::oxideminer_integration::{
    PRODUCTION_FEATURES, REPORT_VERSION, SUPPORTED_RUNTIME_PROFILES, VALIDATION_FEATURES,
};
use serde::{Deserialize, Serialize};

pub const CONTRACT_NAME: &str = "oxideminer-supported-build-contract";
pub const CONTRACT_SCHEMA_VERSION: u32 = 1;
pub const CONTRACT_REVISION: &str = "2026-03-29";

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SupportedBuildContract {
    pub contract_name: String,
    pub schema_version: u32,
    pub contract_revision: String,
    pub intended_consumer: String,
    pub stability_note: String,
    pub crate_identity: CrateIdentity,
    pub provenance: ContractProvenance,
    pub supported_profiles: SupportedProfiles,
    pub supported_runtime_knobs: Vec<RuntimeKnob>,
    pub non_default_experimental_features: Vec<ExperimentalFeature>,
    pub expected_parent_output: ExpectedParentOutput,
    pub example_commands: ExampleCommands,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CrateIdentity {
    pub name: String,
    pub version: String,
    pub repository: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ContractProvenance {
    pub authority_inputs: Vec<String>,
    pub public_reference_surfaces: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SupportedProfiles {
    pub production: BuildProfile,
    pub validation: BuildProfile,
    pub runtime_fallbacks: Vec<RuntimeFallback>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct BuildProfile {
    pub cargo_features: Vec<String>,
    pub supported_runtime_profile: String,
    pub supported_modes: Vec<String>,
    pub purpose: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeFallback {
    pub runtime_profile: String,
    pub required_cargo_features: Vec<String>,
    pub use_when: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeKnob {
    pub name: String,
    pub values: Vec<String>,
    pub default_setting: String,
    pub notes: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ExperimentalFeature {
    pub name: String,
    pub status: String,
    pub default_state: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ExpectedParentOutput {
    pub emitted_by: String,
    pub report_version: String,
    pub top_level_fields: Vec<String>,
    pub session_fields: Vec<String>,
    pub telemetry_fields: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ExampleCommands {
    pub light_validation: String,
    pub fast_validation: String,
}

pub fn current_supported_build_contract() -> SupportedBuildContract {
    SupportedBuildContract {
        contract_name: CONTRACT_NAME.to_string(),
        schema_version: CONTRACT_SCHEMA_VERSION,
        contract_revision: CONTRACT_REVISION.to_string(),
        intended_consumer: "OxideMiner workspace crates".to_string(),
        stability_note: "This is internal OxideMiner contract guidance for the current supported oxide-randomx path. It does not promise that oxide-randomx remains a stable standalone dependency boundary outside OxideMiner; coordinate changes through schema_version, contract_revision, and the owning OxideMiner revision.".to_string(),
        crate_identity: CrateIdentity {
            name: env!("CARGO_PKG_NAME").to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            repository: env!("CARGO_PKG_REPOSITORY").to_string(),
        },
        provenance: ContractProvenance {
            authority_inputs: vec![
                "README.md".to_string(),
                "docs/oxideminer-integration-profile.md".to_string(),
                "docs/oxideminer-integration-harness.md".to_string(),
                "examples/oxideminer_integration.rs".to_string(),
            ],
            public_reference_surfaces: vec![
                "docs/oxideminer-supported-build-contract.md".to_string(),
                "docs/oxideminer-supported-build-contract.json".to_string(),
            ],
        },
        supported_profiles: SupportedProfiles {
            production: BuildProfile {
                cargo_features: split_features(PRODUCTION_FEATURES),
                supported_runtime_profile: "jit-fastregs".to_string(),
                supported_modes: supported_modes(),
                purpose: "Supported shipping profile.".to_string(),
            },
            validation: BuildProfile {
                cargo_features: split_features(VALIDATION_FEATURES),
                supported_runtime_profile: "jit-fastregs".to_string(),
                supported_modes: supported_modes(),
                purpose: "Supported CI, telemetry, perf-gate, and bring-up profile without changing the runtime path.".to_string(),
            },
            runtime_fallbacks: vec![
                RuntimeFallback {
                    runtime_profile: "jit-conservative".to_string(),
                    required_cargo_features: vec!["jit".to_string()],
                    use_when: "JIT is available but fast-register mapping is intentionally disabled or unavailable.".to_string(),
                },
                RuntimeFallback {
                    runtime_profile: "interpreter".to_string(),
                    required_cargo_features: Vec::new(),
                    use_when: "JIT is unavailable or intentionally disabled; this is the lowest-risk supported fallback.".to_string(),
                },
            ],
        },
        supported_runtime_knobs: vec![
            RuntimeKnob {
                name: "mode".to_string(),
                values: supported_modes(),
                default_setting: "Prefer fast when dataset memory is acceptable; use light as the supported cache-only fallback.".to_string(),
                notes: "Both light and fast are part of the supported contract.".to_string(),
            },
            RuntimeKnob {
                name: "runtime_profile".to_string(),
                values: SUPPORTED_RUNTIME_PROFILES
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
                default_setting: "jit-fastregs".to_string(),
                notes: "Maps the parent request onto the supported interpreter, conservative JIT, and fast-regs JIT runtime profiles.".to_string(),
            },
            RuntimeKnob {
                name: "large_pages".to_string(),
                values: vec!["off".to_string(), "on".to_string()],
                default_setting: "off".to_string(),
                notes: "Explicit request knob for scratchpad and Fast-mode dataset backing; verify realized backing from emitted page_backing fields.".to_string(),
            },
            RuntimeKnob {
                name: "use_1gb_pages".to_string(),
                values: vec!["off".to_string(), "on".to_string()],
                default_setting: "off".to_string(),
                notes: "Linux-only Fast-mode dataset request knob; implies large_pages and must be validated from emitted page_backing.dataset fields.".to_string(),
            },
            RuntimeKnob {
                name: "prefetch_calibration_path".to_string(),
                values: vec![
                    "unset".to_string(),
                    "path to persisted calibration csv".to_string(),
                ],
                default_setting: "unset".to_string(),
                notes: "Optional host-local override applied through the public calibration helper; keep the fixed default mapping unless the parent intentionally opts in.".to_string(),
            },
        ],
        non_default_experimental_features: vec![
            ExperimentalFeature {
                name: "simd-blockio".to_string(),
                status: "experimental".to_string(),
                default_state: "off".to_string(),
            },
            ExperimentalFeature {
                name: "simd-xor-paths".to_string(),
                status: "experimental follow-up".to_string(),
                default_state: "off".to_string(),
            },
            ExperimentalFeature {
                name: "threaded-interp".to_string(),
                status: "parked experimental closed negative result".to_string(),
                default_state: "off".to_string(),
            },
            ExperimentalFeature {
                name: "superscalar-accel-proto".to_string(),
                status: "parked experimental research lane".to_string(),
                default_state: "off".to_string(),
            },
        ],
        expected_parent_output: ExpectedParentOutput {
            emitted_by: "examples/oxideminer_integration.rs".to_string(),
            report_version: REPORT_VERSION.to_string(),
            top_level_fields: vec![
                "report_version".to_string(),
                "build_contract".to_string(),
                "requested_runtime_profile".to_string(),
                "requested_flags".to_string(),
                "sessions".to_string(),
            ],
            session_fields: vec![
                "mode".to_string(),
                "lifecycle.requested_runtime_profile".to_string(),
                "lifecycle.effective_runtime_profile".to_string(),
                "lifecycle.fallback_reason".to_string(),
                "lifecycle.jit.requested".to_string(),
                "lifecycle.jit.requested_fast_regs".to_string(),
                "lifecycle.jit.compiled_jit_support".to_string(),
                "lifecycle.jit.compiled_fast_regs_support".to_string(),
                "lifecycle.jit.active".to_string(),
                "requested_flags".to_string(),
                "effective_flags".to_string(),
                "page_backing.scratchpad.request".to_string(),
                "page_backing.scratchpad.realized".to_string(),
                "page_backing.scratchpad.realization".to_string(),
                "page_backing.dataset.request".to_string(),
                "page_backing.dataset.realized".to_string(),
                "page_backing.dataset.realization".to_string(),
                "rekey.parity.matches".to_string(),
                "lifecycle.rekey_matches_rebuild".to_string(),
            ],
            telemetry_fields: vec![
                "telemetry.instrumented".to_string(),
                "telemetry.hashes".to_string(),
                "telemetry.program_execs".to_string(),
                "telemetry.execute_program_ns_interpreter".to_string(),
                "telemetry.execute_program_ns_jit".to_string(),
                "telemetry.finish_iteration_ns".to_string(),
                "telemetry.dataset_item_loads".to_string(),
                "telemetry.scratchpad_read_bytes".to_string(),
                "telemetry.scratchpad_write_bytes".to_string(),
                "telemetry.jit_fastregs_prepare_ns".to_string(),
                "telemetry.jit_fastregs_finish_ns".to_string(),
            ],
        },
        example_commands: ExampleCommands {
            light_validation: format!(
                "cargo run -p oxide-randomx --release --example oxideminer_integration --features \"{VALIDATION_FEATURES}\" -- --mode light --runtime-profile jit-fastregs"
            ),
            fast_validation: format!(
                "cargo run -p oxide-randomx --release --example oxideminer_integration --features \"{VALIDATION_FEATURES}\" -- --mode fast --runtime-profile jit-fastregs"
            ),
        },
    }
}

pub fn current_supported_build_contract_json() -> String {
    serde_json::to_string_pretty(&current_supported_build_contract())
        .expect("serialize supported build contract")
}

fn supported_modes() -> Vec<String> {
    vec!["light".to_string(), "fast".to_string()]
}

fn split_features(features: &str) -> Vec<String> {
    features.split_whitespace().map(str::to_string).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_split_is_stable() {
        assert_eq!(
            split_features(PRODUCTION_FEATURES),
            vec!["jit".to_string(), "jit-fastregs".to_string()]
        );
        assert_eq!(
            split_features(VALIDATION_FEATURES),
            vec![
                "jit".to_string(),
                "jit-fastregs".to_string(),
                "bench-instrument".to_string(),
            ]
        );
    }
}
