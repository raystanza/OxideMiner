use oxide_randomx::oxideminer_integration::{
    format_report_human, format_report_json, run_validation_harness, HarnessModeSelection,
    HarnessOptions, RuntimeProfile, PRODUCTION_FEATURES, VALIDATION_FEATURES,
};
use std::env;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug)]
enum OutputFormat {
    Human,
    Json,
}

fn main() {
    let (opts, format) = parse_args();
    match run_validation_harness(&opts) {
        Ok(report) => match format {
            OutputFormat::Human => print!("{}", format_report_human(&report)),
            OutputFormat::Json => print!("{}", format_report_json(&report)),
        },
        Err(err) => {
            eprintln!("oxideminer_integration error: {err}");
            std::process::exit(1);
        }
    }
}

fn parse_args() -> (HarnessOptions, OutputFormat) {
    let mut opts = HarnessOptions::default();
    let mut format = OutputFormat::Human;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mode" => {
                opts.mode = match args.next().as_deref() {
                    Some("light") => HarnessModeSelection::Light,
                    Some("fast") => HarnessModeSelection::Fast,
                    Some("both") => HarnessModeSelection::Both,
                    _ => usage_and_exit(),
                };
            }
            "--runtime-profile" => {
                opts.runtime_profile = match args.next().as_deref() {
                    Some("interpreter") => RuntimeProfile::Interpreter,
                    Some("jit-conservative") => RuntimeProfile::JitConservative,
                    Some("jit-fastregs") => RuntimeProfile::JitFastRegs,
                    _ => usage_and_exit(),
                };
            }
            "--warmup-rounds" => {
                opts.warmup_rounds = parse_u64(args.next().as_deref());
            }
            "--steady-rounds" => {
                opts.steady_rounds = parse_u64(args.next().as_deref());
            }
            "--threads" => {
                opts.threads = parse_usize(args.next().as_deref());
            }
            "--large-pages" => {
                opts.large_pages = parse_on_off(args.next().as_deref());
            }
            "--use-1gb-pages" => {
                opts.use_1gb_pages = parse_on_off(args.next().as_deref());
            }
            "--calibration" => {
                opts.calibration = Some(PathBuf::from(
                    args.next().unwrap_or_else(|| usage_and_exit()),
                ));
            }
            "--workload-id" => {
                opts.workload_id = args.next().unwrap_or_else(|| usage_and_exit());
            }
            "--format" => {
                format = match args.next().as_deref() {
                    Some("human") => OutputFormat::Human,
                    Some("json") => OutputFormat::Json,
                    _ => usage_and_exit(),
                };
            }
            "--help" | "-h" => usage_and_exit(),
            _ => usage_and_exit(),
        }
    }

    if opts.use_1gb_pages {
        opts.large_pages = true;
    }

    (opts, format)
}

fn usage_and_exit() -> ! {
    eprintln!(
        "Usage: oxideminer_integration [--mode light|fast|both]\n\
         [--runtime-profile interpreter|jit-conservative|jit-fastregs]\n\
         [--warmup-rounds N] [--steady-rounds N] [--threads N]\n\
         [--large-pages on|off] [--use-1gb-pages on|off]\n\
         [--calibration PATH] [--workload-id ID] [--format human|json]\n\
         Supported build contract:\n\
           production = --features \"{PRODUCTION_FEATURES}\"\n\
           validation = --features \"{VALIDATION_FEATURES}\"\n\
         Notes:\n\
           --use-1gb-pages on implies --large-pages on\n\
           1GB huge-page requests apply only to the Fast-mode dataset"
    );
    std::process::exit(1);
}

fn parse_u64(input: Option<&str>) -> u64 {
    input
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_else(|| usage_and_exit())
}

fn parse_usize(input: Option<&str>) -> usize {
    input
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_else(|| usage_and_exit())
}

fn parse_on_off(input: Option<&str>) -> bool {
    match input {
        Some("on") => true,
        Some("off") => false,
        _ => usage_and_exit(),
    }
}
