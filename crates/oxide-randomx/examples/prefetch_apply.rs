use std::env;
use std::path::{Path, PathBuf};

use oxide_randomx::prefetch_calibration::{
    apply_prefetch_calibration_for_current_host, PrefetchCalibrationApplyStatus,
    PrefetchCalibrationMode, PREFETCH_CALIBRATION_WORKLOAD_ID,
};
use oxide_randomx::RandomXFlags;

struct Options {
    calibration: PathBuf,
    mode: PrefetchCalibrationMode,
    workload_id: String,
    scratchpad_prefetch_distance: u8,
    jit_requested: bool,
    jit_fast_regs: bool,
}

fn main() {
    match run(parse_args()) {
        Ok(output) => println!("{output}"),
        Err(err) => {
            eprintln!("prefetch_apply error: {err}");
            std::process::exit(1);
        }
    }
}

fn run(opts: Options) -> Result<String, String> {
    #[cfg(feature = "jit")]
    let mut flags = RandomXFlags {
        scratchpad_prefetch_distance: opts.scratchpad_prefetch_distance,
        jit: opts.jit_requested,
        jit_fast_regs: opts.jit_fast_regs,
        ..RandomXFlags::default()
    };
    #[cfg(not(feature = "jit"))]
    let mut flags = {
        if opts.jit_requested || opts.jit_fast_regs {
            return Err("jit options require --features jit".to_string());
        }
        RandomXFlags {
            scratchpad_prefetch_distance: opts.scratchpad_prefetch_distance,
            ..RandomXFlags::default()
        }
    };

    let outcome = apply_prefetch_calibration_for_current_host(
        &opts.calibration,
        opts.mode,
        &mut flags,
        opts.workload_id,
    )?;

    Ok(format_human(&opts.calibration, &flags, &outcome))
}

fn parse_args() -> Options {
    let mut calibration = None;
    let mut mode = PrefetchCalibrationMode::Light;
    let mut workload_id = PREFETCH_CALIBRATION_WORKLOAD_ID.to_string();
    let mut scratchpad_prefetch_distance = 0u8;
    let mut jit_requested = false;
    let mut jit_fast_regs = false;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--calibration" => {
                calibration = Some(PathBuf::from(
                    args.next().unwrap_or_else(|| usage_and_exit()),
                ));
            }
            "--mode" => {
                mode = match args.next().as_deref() {
                    Some("light") => PrefetchCalibrationMode::Light,
                    Some("fast") => PrefetchCalibrationMode::Fast,
                    _ => usage_and_exit(),
                };
            }
            "--workload-id" => {
                workload_id = args.next().unwrap_or_else(|| usage_and_exit());
            }
            "--scratchpad-prefetch-distance" => {
                scratchpad_prefetch_distance = parse_u8(args.next().as_deref());
                if scratchpad_prefetch_distance > 32 {
                    usage_and_exit();
                }
            }
            "--jit" => {
                jit_requested = parse_on_off(args.next().as_deref());
            }
            "--jit-fast-regs" => {
                jit_fast_regs = parse_on_off(args.next().as_deref());
            }
            "--help" | "-h" => usage_and_exit(),
            _ => usage_and_exit(),
        }
    }

    Options {
        calibration: calibration.unwrap_or_else(|| usage_and_exit()),
        mode,
        workload_id,
        scratchpad_prefetch_distance,
        jit_requested,
        jit_fast_regs,
    }
}

fn parse_u8(input: Option<&str>) -> u8 {
    input
        .and_then(|value| value.parse::<u8>().ok())
        .unwrap_or_else(|| usage_and_exit())
}

fn parse_on_off(input: Option<&str>) -> bool {
    match input {
        Some("on") => true,
        Some("off") => false,
        _ => usage_and_exit(),
    }
}

fn usage_and_exit() -> ! {
    eprintln!(
        "Usage: prefetch_apply --calibration PATH [--mode light|fast] [--jit on|off]\n\
         [--jit-fast-regs on|off] [--scratchpad-prefetch-distance N] [--workload-id ID]"
    );
    std::process::exit(1);
}

fn format_human(
    calibration: &Path,
    flags: &RandomXFlags,
    outcome: &oxide_randomx::prefetch_calibration::PrefetchCalibrationApplyOutcome,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("calibration_path={}\n", calibration.display()));
    out.push_str(&format!("status={:?}\n", outcome.status));
    out.push_str(&format!(
        "effective_flags prefetch={} prefetch_distance={} prefetch_auto_tune={} scratchpad_prefetch_distance={}\n",
        flags.prefetch,
        flags.prefetch_distance,
        flags.prefetch_auto_tune,
        flags.scratchpad_prefetch_distance
    ));
    match outcome.status {
        PrefetchCalibrationApplyStatus::Applied => {
            let record = outcome.record.as_ref().expect("applied record");
            out.push_str(&format!(
                "matched cpu={} family={} model={} stepping={} bucket=\"{}\"\n",
                record.cpu.vendor,
                record.cpu.family,
                record.cpu.model,
                record.cpu.stepping,
                record.cpu.family_bucket
            ));
            out.push_str(&format!(
                "matched scenario mode={} jit_requested={} jit_fast_regs={} workload_id={} scratchpad_prefetch_distance={}\n",
                record.scenario.mode,
                record.scenario.jit_requested,
                record.scenario.jit_fast_regs,
                record.scenario.workload_id,
                record.scenario.scratchpad_prefetch_distance
            ));
            out.push_str(&format!(
                "applied best_prefetch_distance={} best_ns_per_hash={}\n",
                record.best_prefetch_distance, record.best_ns_per_hash
            ));
        }
        PrefetchCalibrationApplyStatus::NoCalibrationFile => {
            out.push_str("fallback=calibration file missing; flags unchanged\n");
        }
        PrefetchCalibrationApplyStatus::NoMatchingCalibration => {
            out.push_str("fallback=no strict current-host match; flags unchanged\n");
        }
    }
    out
}
