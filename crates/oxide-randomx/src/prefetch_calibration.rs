//! Host-local prefetch calibration persistence and keying helpers.
//!
//! This module intentionally does not change runtime defaults. It provides
//! bounded, traceable storage/query primitives used by opt-in tooling.

use std::fs;
use std::path::Path;

use crate::flags;
use crate::flags::RandomXFlags;

/// CSV schema version for persisted calibration rows.
pub const PREFETCH_CALIBRATION_SCHEMA_VERSION: u32 = 1;

/// Default workload identifier used by the calibration helper.
pub const PREFETCH_CALIBRATION_WORKLOAD_ID: &str = "prefetch_calibrate_workload_v1";

/// Runtime mode used to key a calibration scenario.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrefetchCalibrationMode {
    Light,
    Fast,
}

impl PrefetchCalibrationMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Fast => "fast",
        }
    }
}

/// CPU identity bucket used for host-local calibration keying.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefetchCpuIdentity {
    pub vendor: String,
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
    pub family_bucket: String,
}

impl PrefetchCpuIdentity {
    #[must_use]
    pub fn current() -> Self {
        detect_cpu_identity()
    }
}

/// Build/code identity used to invalidate stale calibration entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefetchCodeIdentity {
    pub schema_version: u32,
    pub crate_version: String,
    pub git_sha: String,
    pub git_dirty: String,
    pub rustc: String,
}

impl PrefetchCodeIdentity {
    #[must_use]
    pub fn current() -> Self {
        Self {
            schema_version: PREFETCH_CALIBRATION_SCHEMA_VERSION,
            crate_version: env!("CARGO_PKG_VERSION").to_string(),
            git_sha: option_env!("OXIDE_RANDOMX_GIT_SHA")
                .unwrap_or("unknown")
                .to_string(),
            git_dirty: option_env!("OXIDE_RANDOMX_GIT_DIRTY")
                .unwrap_or("unknown")
                .to_string(),
            rustc: option_env!("OXIDE_RANDOMX_RUSTC_VERSION")
                .unwrap_or("unknown")
                .to_string(),
        }
    }
}

/// Scenario key for mode-aware calibration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefetchScenarioKey {
    pub mode: String,
    pub jit_requested: bool,
    pub jit_fast_regs: bool,
    pub scratchpad_prefetch_distance: u8,
    pub workload_id: String,
}

impl PrefetchScenarioKey {
    #[must_use]
    pub fn new(
        mode: impl Into<String>,
        jit_requested: bool,
        jit_fast_regs: bool,
        scratchpad_prefetch_distance: u8,
        workload_id: impl Into<String>,
    ) -> Self {
        Self {
            mode: mode.into(),
            jit_requested,
            jit_fast_regs,
            scratchpad_prefetch_distance,
            workload_id: workload_id.into(),
        }
    }

    /// Build a scenario key from runtime mode + flags.
    #[must_use]
    pub fn from_runtime(
        mode: PrefetchCalibrationMode,
        flags: &RandomXFlags,
        workload_id: impl Into<String>,
    ) -> Self {
        Self::new(
            mode.as_str(),
            flags_jit_requested(flags),
            flags_jit_fast_regs(flags),
            flags.scratchpad_prefetch_distance,
            workload_id,
        )
    }
}

/// One persisted calibration result row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefetchCalibrationRecord {
    pub code: PrefetchCodeIdentity,
    pub cpu: PrefetchCpuIdentity,
    pub scenario: PrefetchScenarioKey,
    pub best_prefetch_distance: u8,
    pub best_ns_per_hash: u64,
    pub rounds: u32,
    pub iters_per_round: u64,
    pub warmup_per_round: u64,
    pub calibrated_at_unix_secs: u64,
}

/// Lookup key for selecting a compatible persisted calibration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefetchCalibrationQuery {
    pub code: PrefetchCodeIdentity,
    pub cpu: PrefetchCpuIdentity,
    pub scenario: PrefetchScenarioKey,
}

impl PrefetchCalibrationQuery {
    #[must_use]
    pub fn new(
        code: PrefetchCodeIdentity,
        cpu: PrefetchCpuIdentity,
        scenario: PrefetchScenarioKey,
    ) -> Self {
        Self {
            code,
            cpu,
            scenario,
        }
    }

    /// Build a query from explicit runtime identities.
    #[must_use]
    pub fn from_runtime(
        code: PrefetchCodeIdentity,
        cpu: PrefetchCpuIdentity,
        mode: PrefetchCalibrationMode,
        flags: &RandomXFlags,
        workload_id: impl Into<String>,
    ) -> Self {
        Self::new(
            code,
            cpu,
            PrefetchScenarioKey::from_runtime(mode, flags, workload_id),
        )
    }

    /// Build a query for the current host/build/runtime shape.
    #[must_use]
    pub fn for_current_host(
        mode: PrefetchCalibrationMode,
        flags: &RandomXFlags,
        workload_id: impl Into<String>,
    ) -> Self {
        Self::from_runtime(
            PrefetchCodeIdentity::current(),
            PrefetchCpuIdentity::current(),
            mode,
            flags,
            workload_id,
        )
    }
}

/// Result of attempting to apply a persisted calibration row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefetchCalibrationApplyOutcome {
    pub status: PrefetchCalibrationApplyStatus,
    pub record: Option<PrefetchCalibrationRecord>,
}

/// Explicit fallback status for the runtime apply path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrefetchCalibrationApplyStatus {
    Applied,
    NoCalibrationFile,
    NoMatchingCalibration,
}

impl PrefetchCalibrationRecord {
    #[must_use]
    pub fn header() -> &'static str {
        "schema_version,crate_version,git_sha,git_dirty,rustc,cpu_vendor,cpu_family,\
cpu_model,cpu_stepping,cpu_family_bucket,mode,jit_requested,jit_fast_regs,\
scratchpad_prefetch_distance,workload_id,best_prefetch_distance,best_ns_per_hash,\
rounds,iters_per_round,warmup_per_round,calibrated_at_unix_secs"
    }

    #[must_use]
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.code.schema_version,
            self.code.crate_version,
            self.code.git_sha,
            self.code.git_dirty,
            self.code.rustc,
            self.cpu.vendor,
            self.cpu.family,
            self.cpu.model,
            self.cpu.stepping,
            self.cpu.family_bucket,
            self.scenario.mode,
            self.scenario.jit_requested,
            self.scenario.jit_fast_regs,
            self.scenario.scratchpad_prefetch_distance,
            self.scenario.workload_id,
            self.best_prefetch_distance,
            self.best_ns_per_hash,
            self.rounds,
            self.iters_per_round,
            self.warmup_per_round,
            self.calibrated_at_unix_secs
        )
    }

    pub fn from_csv_row(line: &str) -> Result<Self, String> {
        let cols = line.split(',').collect::<Vec<_>>();
        if cols.len() != 21 {
            return Err(format!("expected 21 columns, got {}", cols.len()));
        }
        let parse_u32 = |idx: usize| -> Result<u32, String> {
            cols[idx]
                .parse::<u32>()
                .map_err(|_| format!("invalid u32 at column {idx}: {}", cols[idx]))
        };
        let parse_u64 = |idx: usize| -> Result<u64, String> {
            cols[idx]
                .parse::<u64>()
                .map_err(|_| format!("invalid u64 at column {idx}: {}", cols[idx]))
        };
        let parse_u8 = |idx: usize| -> Result<u8, String> {
            cols[idx]
                .parse::<u8>()
                .map_err(|_| format!("invalid u8 at column {idx}: {}", cols[idx]))
        };
        let parse_bool = |idx: usize| -> Result<bool, String> {
            cols[idx]
                .parse::<bool>()
                .map_err(|_| format!("invalid bool at column {idx}: {}", cols[idx]))
        };

        Ok(Self {
            code: PrefetchCodeIdentity {
                schema_version: parse_u32(0)?,
                crate_version: cols[1].to_string(),
                git_sha: cols[2].to_string(),
                git_dirty: cols[3].to_string(),
                rustc: cols[4].to_string(),
            },
            cpu: PrefetchCpuIdentity {
                vendor: cols[5].to_string(),
                family: parse_u32(6)?,
                model: parse_u32(7)?,
                stepping: parse_u32(8)?,
                family_bucket: cols[9].to_string(),
            },
            scenario: PrefetchScenarioKey {
                mode: cols[10].to_string(),
                jit_requested: parse_bool(11)?,
                jit_fast_regs: parse_bool(12)?,
                scratchpad_prefetch_distance: parse_u8(13)?,
                workload_id: cols[14].to_string(),
            },
            best_prefetch_distance: parse_u8(15)?,
            best_ns_per_hash: parse_u64(16)?,
            rounds: parse_u32(17)?,
            iters_per_round: parse_u64(18)?,
            warmup_per_round: parse_u64(19)?,
            calibrated_at_unix_secs: parse_u64(20)?,
        })
    }

    #[must_use]
    pub fn matches_query(&self, query: &PrefetchCalibrationQuery) -> bool {
        self.code == query.code && self.cpu == query.cpu && self.scenario == query.scenario
    }
}

/// Read persisted calibration rows from `path`.
pub fn load_calibration_records(path: &Path) -> Result<Vec<PrefetchCalibrationRecord>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut lines = content.lines();
    let Some(header) = lines.next() else {
        return Ok(Vec::new());
    };
    if header.trim() != PrefetchCalibrationRecord::header() {
        return Err(format!(
            "unexpected calibration header in {}",
            path.display()
        ));
    }
    let mut out = Vec::new();
    for (idx, line) in lines.enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let row = PrefetchCalibrationRecord::from_csv_row(line)
            .map_err(|e| format!("parse row {}: {e}", idx + 2))?;
        out.push(row);
    }
    Ok(out)
}

/// Write calibration rows to `path`, replacing existing file content.
pub fn write_calibration_records(
    path: &Path,
    records: &[PrefetchCalibrationRecord],
) -> Result<(), String> {
    let mut out = String::new();
    out.push_str(PrefetchCalibrationRecord::header());
    out.push('\n');
    for record in records {
        out.push_str(&record.to_csv_row());
        out.push('\n');
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    fs::write(path, out).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Insert or replace a single record keyed by full `(code,cpu,scenario)` identity.
pub fn upsert_calibration_record(
    path: &Path,
    record: PrefetchCalibrationRecord,
) -> Result<(), String> {
    let mut rows = load_calibration_records(path)?;
    if let Some(idx) = rows.iter().position(|existing| {
        existing.code == record.code
            && existing.cpu == record.cpu
            && existing.scenario == record.scenario
    }) {
        rows[idx] = record;
    } else {
        rows.push(record);
    }
    write_calibration_records(path, &rows)
}

/// Select a compatible persisted calibration row for `query`.
pub fn select_calibration_record(
    path: &Path,
    query: &PrefetchCalibrationQuery,
) -> Result<Option<PrefetchCalibrationRecord>, String> {
    let rows = load_calibration_records(path)?;
    Ok(rows.into_iter().find(|row| row.matches_query(query)))
}

/// Load a persisted calibration row that matches the current host/build/runtime shape.
pub fn load_prefetch_calibration_for_current_host(
    path: &Path,
    mode: PrefetchCalibrationMode,
    flags: &RandomXFlags,
    workload_id: impl Into<String>,
) -> Result<Option<PrefetchCalibrationRecord>, String> {
    let query = PrefetchCalibrationQuery::for_current_host(mode, flags, workload_id);
    select_calibration_record(path, &query)
}

/// Apply one calibration record to runtime flags.
pub fn apply_prefetch_calibration_record(
    flags: &mut RandomXFlags,
    record: &PrefetchCalibrationRecord,
) {
    let distance = record.best_prefetch_distance;
    flags.prefetch = distance != 0;
    flags.prefetch_distance = distance;
    // Persisted host-local calibration is an explicit override, not a request to
    // re-run the family-table mapping.
    flags.prefetch_auto_tune = false;
}

/// Load and apply a matching persisted calibration for the current host/build/runtime shape.
///
/// Safe fallback semantics:
/// - missing file => `NoCalibrationFile`, flags unchanged
/// - file present but no strict match => `NoMatchingCalibration`, flags unchanged
/// - malformed file => `Err(...)`, caller decides whether to log and continue
pub fn apply_prefetch_calibration_for_current_host(
    path: &Path,
    mode: PrefetchCalibrationMode,
    flags: &mut RandomXFlags,
    workload_id: impl Into<String>,
) -> Result<PrefetchCalibrationApplyOutcome, String> {
    if !path.exists() {
        return Ok(PrefetchCalibrationApplyOutcome {
            status: PrefetchCalibrationApplyStatus::NoCalibrationFile,
            record: None,
        });
    }

    let record = load_prefetch_calibration_for_current_host(path, mode, flags, workload_id)?;
    match record {
        Some(record) => {
            apply_prefetch_calibration_record(flags, &record);
            Ok(PrefetchCalibrationApplyOutcome {
                status: PrefetchCalibrationApplyStatus::Applied,
                record: Some(record),
            })
        }
        None => Ok(PrefetchCalibrationApplyOutcome {
            status: PrefetchCalibrationApplyStatus::NoMatchingCalibration,
            record: None,
        }),
    }
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
fn flags_jit_fast_regs(flags: &RandomXFlags) -> bool {
    flags.jit_fast_regs
}

#[cfg(not(feature = "jit"))]
fn flags_jit_fast_regs(_flags: &RandomXFlags) -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
fn detect_cpu_identity() -> PrefetchCpuIdentity {
    #[cfg(miri)]
    {
        return PrefetchCpuIdentity {
            vendor: "miri".to_string(),
            family: 0,
            model: 0,
            stepping: 0,
            family_bucket: "Unknown".to_string(),
        };
    }
    #[cfg(not(miri))]
    {
        use std::arch::x86_64::__cpuid;
        // This runs only on x86_64, where CPUID is a stable userspace
        // instruction. Leaves 0 and 1 only read CPU identification registers.
        let (cpuid0, cpuid1) = (__cpuid(0), __cpuid(1));
        let mut vendor_bytes = [0u8; 12];
        vendor_bytes[..4].copy_from_slice(&cpuid0.ebx.to_le_bytes());
        vendor_bytes[4..8].copy_from_slice(&cpuid0.edx.to_le_bytes());
        vendor_bytes[8..12].copy_from_slice(&cpuid0.ecx.to_le_bytes());
        let vendor = String::from_utf8_lossy(&vendor_bytes).into_owned();
        let eax = cpuid1.eax;
        let base_family = (eax >> 8) & 0xF;
        let ext_family = (eax >> 20) & 0xFF;
        let family = if base_family == 15 {
            base_family + ext_family
        } else {
            base_family
        };
        let base_model = (eax >> 4) & 0xF;
        let ext_model = (eax >> 16) & 0xF;
        let model = if base_family == 6 || base_family == 15 {
            base_model | (ext_model << 4)
        } else {
            base_model
        };
        let stepping = eax & 0xF;
        let family_bucket = flags::cpu_detect::detect_cpu_family()
            .name()
            .replace(',', "");
        PrefetchCpuIdentity {
            vendor,
            family,
            model,
            stepping,
            family_bucket,
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn detect_cpu_identity() -> PrefetchCpuIdentity {
    PrefetchCpuIdentity {
        vendor: "unknown".to_string(),
        family: 0,
        model: 0,
        stepping: 0,
        family_bucket: "Unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sample_record() -> PrefetchCalibrationRecord {
        PrefetchCalibrationRecord {
            code: PrefetchCodeIdentity {
                schema_version: PREFETCH_CALIBRATION_SCHEMA_VERSION,
                crate_version: "0.1.0".to_string(),
                git_sha: "abc".to_string(),
                git_dirty: "false".to_string(),
                rustc: "rustc".to_string(),
            },
            cpu: PrefetchCpuIdentity {
                vendor: "GenuineIntel".to_string(),
                family: 6,
                model: 85,
                stepping: 7,
                family_bucket: "Intel Skylake-era".to_string(),
            },
            scenario: PrefetchScenarioKey::new(
                "light",
                false,
                false,
                0,
                PREFETCH_CALIBRATION_WORKLOAD_ID,
            ),
            best_prefetch_distance: 3,
            best_ns_per_hash: 12345,
            rounds: 3,
            iters_per_round: 50,
            warmup_per_round: 5,
            calibrated_at_unix_secs: 1_700_000_000,
        }
    }

    #[cfg(feature = "jit")]
    fn scenario_flags(
        scratchpad_prefetch_distance: u8,
        jit: bool,
        jit_fast_regs: bool,
    ) -> RandomXFlags {
        RandomXFlags {
            prefetch: false,
            prefetch_distance: 0,
            prefetch_auto_tune: true,
            scratchpad_prefetch_distance,
            jit,
            jit_fast_regs,
            ..RandomXFlags::default()
        }
    }

    #[cfg(not(feature = "jit"))]
    fn scenario_flags(
        scratchpad_prefetch_distance: u8,
        _jit: bool,
        _jit_fast_regs: bool,
    ) -> RandomXFlags {
        RandomXFlags {
            prefetch: false,
            prefetch_distance: 0,
            prefetch_auto_tune: true,
            scratchpad_prefetch_distance,
            ..RandomXFlags::default()
        }
    }

    fn temp_csv_path(suffix: &str) -> std::path::PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "oxide-randomx-prefetch-calibration-{suffix}-{now}.csv"
        ))
    }

    fn current_host_record(
        flags: &RandomXFlags,
        mode: PrefetchCalibrationMode,
        workload_id: &str,
    ) -> PrefetchCalibrationRecord {
        let query = PrefetchCalibrationQuery::for_current_host(mode, flags, workload_id);
        PrefetchCalibrationRecord {
            code: query.code,
            cpu: query.cpu,
            scenario: query.scenario,
            best_prefetch_distance: 5,
            best_ns_per_hash: 12_345,
            rounds: 3,
            iters_per_round: 50,
            warmup_per_round: 5,
            calibrated_at_unix_secs: 1_700_000_000,
        }
    }

    #[test]
    fn calibration_record_round_trips_csv() {
        let row = sample_record().to_csv_row();
        let parsed = PrefetchCalibrationRecord::from_csv_row(&row).expect("parse");
        assert_eq!(parsed, sample_record());
    }

    #[test]
    fn scenario_key_from_runtime_uses_flags_shape() {
        let flags = scenario_flags(7, true, true);

        let scenario =
            PrefetchScenarioKey::from_runtime(PrefetchCalibrationMode::Fast, &flags, "test-id");
        assert_eq!(scenario.mode, "fast");
        assert_eq!(scenario.scratchpad_prefetch_distance, 7);
        assert_eq!(scenario.workload_id, "test-id");
        #[cfg(feature = "jit")]
        {
            assert!(scenario.jit_requested);
            assert!(scenario.jit_fast_regs);
        }
        #[cfg(not(feature = "jit"))]
        {
            assert!(!scenario.jit_requested);
            assert!(!scenario.jit_fast_regs);
        }
    }

    #[test]
    fn select_calibration_requires_full_key_match() {
        let path = temp_csv_path("select");
        let record = sample_record();
        upsert_calibration_record(&path, record.clone()).expect("upsert");

        let query = PrefetchCalibrationQuery {
            code: record.code.clone(),
            cpu: record.cpu.clone(),
            scenario: record.scenario.clone(),
        };
        let got = select_calibration_record(&path, &query)
            .expect("select")
            .expect("record");
        assert_eq!(got.best_prefetch_distance, 3);

        let mut mismatched_code = query.clone();
        mismatched_code.code.git_sha = "different".to_string();
        assert!(select_calibration_record(&path, &mismatched_code)
            .expect("select")
            .is_none());

        let mut mismatched_mode = query.clone();
        mismatched_mode.scenario.mode = "fast".to_string();
        assert!(select_calibration_record(&path, &mismatched_mode)
            .expect("select")
            .is_none());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn upsert_replaces_matching_identity_row() {
        let path = temp_csv_path("upsert");
        let mut record = sample_record();
        upsert_calibration_record(&path, record.clone()).expect("first");

        record.best_prefetch_distance = 4;
        record.best_ns_per_hash = 11111;
        upsert_calibration_record(&path, record.clone()).expect("second");

        let rows = load_calibration_records(&path).expect("load");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].best_prefetch_distance, 4);
        assert_eq!(rows[0].best_ns_per_hash, 11111);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_current_host_prefetch_calibration_updates_flags() {
        let path = temp_csv_path("apply");
        let workload_id = "prefetch-apply-test";
        let mut flags = scenario_flags(4, false, false);
        let record = current_host_record(&flags, PrefetchCalibrationMode::Light, workload_id);
        upsert_calibration_record(&path, record.clone()).expect("upsert");

        let outcome = apply_prefetch_calibration_for_current_host(
            &path,
            PrefetchCalibrationMode::Light,
            &mut flags,
            workload_id,
        )
        .expect("apply");

        assert_eq!(outcome.status, PrefetchCalibrationApplyStatus::Applied);
        assert_eq!(outcome.record, Some(record));
        assert!(flags.prefetch);
        assert_eq!(flags.prefetch_distance, 5);
        assert!(!flags.prefetch_auto_tune);
        assert_eq!(flags.scratchpad_prefetch_distance, 4);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_current_host_prefetch_calibration_keeps_flags_when_file_missing() {
        let path = temp_csv_path("missing");
        let mut flags = scenario_flags(3, false, false);

        let outcome = apply_prefetch_calibration_for_current_host(
            &path,
            PrefetchCalibrationMode::Light,
            &mut flags,
            "missing-file-test",
        )
        .expect("apply");

        assert_eq!(
            outcome.status,
            PrefetchCalibrationApplyStatus::NoCalibrationFile
        );
        assert!(outcome.record.is_none());
        assert!(!flags.prefetch);
        assert_eq!(flags.prefetch_distance, 0);
        assert!(flags.prefetch_auto_tune);
        assert_eq!(flags.scratchpad_prefetch_distance, 3);
    }

    #[test]
    fn apply_current_host_prefetch_calibration_requires_strict_match() {
        let path = temp_csv_path("mismatch");
        let mut flags = scenario_flags(1, false, false);
        let record =
            current_host_record(&flags, PrefetchCalibrationMode::Light, "strict-match-test");
        upsert_calibration_record(&path, record).expect("upsert");

        flags.scratchpad_prefetch_distance = 2;
        let outcome = apply_prefetch_calibration_for_current_host(
            &path,
            PrefetchCalibrationMode::Light,
            &mut flags,
            "strict-match-test",
        )
        .expect("apply");

        assert_eq!(
            outcome.status,
            PrefetchCalibrationApplyStatus::NoMatchingCalibration
        );
        assert!(outcome.record.is_none());
        assert!(!flags.prefetch);
        assert_eq!(flags.prefetch_distance, 0);
        assert!(flags.prefetch_auto_tune);
        assert_eq!(flags.scratchpad_prefetch_distance, 2);

        let _ = fs::remove_file(path);
    }
}
