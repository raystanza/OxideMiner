use oxide_randomx::oxideminer_supported_build_contract::{
    current_supported_build_contract, SupportedBuildContract, CONTRACT_NAME, CONTRACT_REVISION,
    CONTRACT_SCHEMA_VERSION,
};
use std::fs;
use std::path::Path;

#[test]
fn checked_in_json_matches_generated_contract() {
    let expected = current_supported_build_contract();
    let json_path = Path::new("docs/oxideminer-supported-build-contract.json");
    let actual: SupportedBuildContract =
        serde_json::from_str(&fs::read_to_string(json_path).expect("read json contract"))
            .expect("parse json contract");

    assert_eq!(actual, expected);
}

#[test]
fn markdown_and_json_agree_on_key_fields() {
    let contract = current_supported_build_contract();
    let markdown = fs::read_to_string("docs/oxideminer-supported-build-contract.md")
        .expect("read markdown contract");

    assert!(markdown.contains(&format!("Schema version: `{CONTRACT_SCHEMA_VERSION}`")));
    assert!(markdown.contains(&format!("Contract name: `{CONTRACT_NAME}`")));
    assert!(markdown.contains(&format!("Contract revision: `{CONTRACT_REVISION}`")));
    assert!(markdown.contains(&format!(
        "Crate: `{}` `{}`",
        contract.crate_identity.name, contract.crate_identity.version
    )));
    assert!(markdown.contains(&format!(
        "Repository: `{}`",
        contract.crate_identity.repository
    )));
    assert!(markdown.contains("`jit jit-fastregs`"));
    assert!(markdown.contains("`jit jit-fastregs bench-instrument`"));
    assert!(markdown.contains("`oxideminer-integration-v2`"));
    assert!(markdown.contains(&format!("`{}`", contract.example_commands.light_validation)));
    assert!(markdown.contains(&format!("`{}`", contract.example_commands.fast_validation)));

    for feature in &contract.non_default_experimental_features {
        assert!(markdown.contains(&format!("`{}`", feature.name)));
    }

    for field in &contract.expected_parent_output.top_level_fields {
        assert!(markdown.contains(&format!("`{field}`")));
    }

    for field in &[
        "page_backing.dataset.realization",
        "rekey.parity.matches",
        "telemetry.execute_program_ns_jit",
    ] {
        assert!(markdown.contains(&format!("`{field}`")));
    }
}
