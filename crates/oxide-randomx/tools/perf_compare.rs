use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

#[derive(Debug)]
struct Options {
    baseline: PathBuf,
    candidate: PathBuf,
    threshold_pct: f64,
}

#[derive(Debug)]
struct CsvStats {
    path: PathBuf,
    rows: usize,
    mean_ns_per_hash: f64,
    min_ns_per_hash: f64,
    max_ns_per_hash: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    PassImprovement,
    PassWithinThreshold,
    FailRegression,
}

fn main() {
    let opts = match parse_args() {
        Ok(opts) => opts,
        Err(msg) => {
            eprintln!("{msg}");
            print_usage();
            process::exit(2);
        }
    };

    let baseline = match read_csv_stats(&opts.baseline) {
        Ok(stats) => stats,
        Err(msg) => {
            eprintln!("error: {msg}");
            process::exit(2);
        }
    };

    let candidate = match read_csv_stats(&opts.candidate) {
        Ok(stats) => stats,
        Err(msg) => {
            eprintln!("error: {msg}");
            process::exit(2);
        }
    };

    let delta_pct = percent_delta(baseline.mean_ns_per_hash, candidate.mean_ns_per_hash);
    let decision = evaluate(delta_pct, opts.threshold_pct);

    println!("perf_compare summary");
    println!(
        "baseline path={} rows={} mean_ns_per_hash={:.3} min={:.3} max={:.3}",
        baseline.path.display(),
        baseline.rows,
        baseline.mean_ns_per_hash,
        baseline.min_ns_per_hash,
        baseline.max_ns_per_hash
    );
    println!(
        "candidate path={} rows={} mean_ns_per_hash={:.3} min={:.3} max={:.3}",
        candidate.path.display(),
        candidate.rows,
        candidate.mean_ns_per_hash,
        candidate.min_ns_per_hash,
        candidate.max_ns_per_hash
    );
    println!(
        "delta baseline_to_candidate={:+.3}% threshold={:.3}%",
        delta_pct, opts.threshold_pct
    );

    match decision {
        Decision::PassImprovement => {
            println!("result=PASS candidate is faster than baseline");
            process::exit(0);
        }
        Decision::PassWithinThreshold => {
            println!("result=PASS regression is within threshold");
            process::exit(0);
        }
        Decision::FailRegression => {
            println!("result=FAIL regression exceeds threshold");
            process::exit(1);
        }
    }
}

fn parse_args() -> Result<Options, String> {
    let mut baseline = None::<PathBuf>;
    let mut candidate = None::<PathBuf>;
    let mut threshold_pct = 2.0f64;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--baseline" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for --baseline".to_string())?;
                baseline = Some(PathBuf::from(value));
            }
            "--candidate" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for --candidate".to_string())?;
                candidate = Some(PathBuf::from(value));
            }
            "--threshold-pct" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for --threshold-pct".to_string())?;
                threshold_pct = value.parse::<f64>().map_err(|_| {
                    format!("invalid --threshold-pct value: {value} (expected number)")
                })?;
            }
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    let baseline = baseline.ok_or_else(|| "missing required --baseline <path>".to_string())?;
    let candidate = candidate.ok_or_else(|| "missing required --candidate <path>".to_string())?;

    if !threshold_pct.is_finite() || threshold_pct < 0.0 {
        return Err(format!(
            "invalid --threshold-pct value: {threshold_pct} (must be finite and >= 0)"
        ));
    }

    Ok(Options {
        baseline,
        candidate,
        threshold_pct,
    })
}

fn print_usage() {
    eprintln!(
        "Usage: perf_compare --baseline <path> --candidate <path> [--threshold-pct <number>]\n\
         Example:\n\
           cargo run --release --bin perf_compare -- \\\n\
             --baseline perf_results/baseline.csv \\\n\
             --candidate perf_results/candidate.csv \\\n\
             --threshold-pct 2.0"
    );
}

fn read_csv_stats(path: &Path) -> Result<CsvStats, String> {
    let content = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;

    if content.trim().is_empty() {
        return Err(format!("CSV is empty: {}", path.display()));
    }

    let mut lines = content.lines().enumerate().filter_map(|(idx, line)| {
        if line.trim().is_empty() {
            None
        } else {
            Some((idx + 1, line))
        }
    });

    let (header_line_no, header_line) = lines
        .next()
        .ok_or_else(|| format!("CSV has no header: {}", path.display()))?;
    let headers = parse_csv_record(header_line).map_err(|err| {
        format!(
            "failed to parse header at {}:{}: {err}",
            path.display(),
            header_line_no
        )
    })?;

    let ns_idx = headers
        .iter()
        .position(|h| h.trim() == "ns_per_hash")
        .ok_or_else(|| format!("missing 'ns_per_hash' column in {}", path.display()))?;

    let mut count = 0usize;
    let mut sum = 0.0f64;
    let mut min = f64::INFINITY;
    let mut max = f64::NEG_INFINITY;

    for (line_no, line) in lines {
        let row = parse_csv_record(line).map_err(|err| {
            format!(
                "failed to parse row at {}:{}: {err}",
                path.display(),
                line_no
            )
        })?;

        if ns_idx >= row.len() {
            return Err(format!(
                "row {} in {} has no ns_per_hash value",
                line_no,
                path.display()
            ));
        }

        let raw = row[ns_idx].trim();
        let value = raw.parse::<f64>().map_err(|_| {
            format!(
                "invalid ns_per_hash value '{}' at {}:{}",
                raw,
                path.display(),
                line_no
            )
        })?;

        if !value.is_finite() || value <= 0.0 {
            return Err(format!(
                "invalid ns_per_hash value '{}' at {}:{} (must be finite and > 0)",
                raw,
                path.display(),
                line_no
            ));
        }

        count += 1;
        sum += value;
        if value < min {
            min = value;
        }
        if value > max {
            max = value;
        }
    }

    if count == 0 {
        return Err(format!(
            "CSV has header but no data rows: {}",
            path.display()
        ));
    }

    Ok(CsvStats {
        path: path.to_path_buf(),
        rows: count,
        mean_ns_per_hash: sum / count as f64,
        min_ns_per_hash: min,
        max_ns_per_hash: max,
    })
}

fn parse_csv_record(line: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut field = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes = false;

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                if in_quotes {
                    if matches!(chars.peek(), Some('"')) {
                        field.push('"');
                        chars.next();
                    } else {
                        in_quotes = false;
                    }
                } else if field.is_empty() {
                    in_quotes = true;
                } else {
                    return Err("unexpected quote character".to_string());
                }
            }
            ',' if !in_quotes => {
                out.push(std::mem::take(&mut field));
            }
            _ => field.push(ch),
        }
    }

    if in_quotes {
        return Err("unterminated quoted field".to_string());
    }

    out.push(field);
    Ok(out)
}

fn percent_delta(baseline: f64, candidate: f64) -> f64 {
    ((candidate - baseline) / baseline) * 100.0
}

fn evaluate(delta_pct: f64, threshold_pct: f64) -> Decision {
    if delta_pct <= 0.0 {
        Decision::PassImprovement
    } else if delta_pct <= threshold_pct {
        Decision::PassWithinThreshold
    } else {
        Decision::FailRegression
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn write_temp_csv(contents: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = env::temp_dir().join(format!("perf_compare_test_{nanos}.csv"));
        fs::write(&path, contents).expect("write temp csv");
        path
    }

    #[test]
    fn parse_csv_record_handles_quotes() {
        let row = parse_csv_record("a,\"b,c\",d").expect("parse");
        assert_eq!(row, vec!["a", "b,c", "d"]);
    }

    #[test]
    fn parse_csv_record_rejects_unterminated_quote() {
        let err = parse_csv_record("a,\"b").expect_err("should fail");
        assert!(err.contains("unterminated"));
    }

    #[test]
    fn evaluate_threshold_logic() {
        assert_eq!(evaluate(-1.0, 2.0), Decision::PassImprovement);
        assert_eq!(evaluate(0.5, 2.0), Decision::PassWithinThreshold);
        assert_eq!(evaluate(2.5, 2.0), Decision::FailRegression);
    }

    #[test]
    fn percent_delta_signs() {
        let faster = percent_delta(100.0, 90.0);
        let slower = percent_delta(100.0, 110.0);
        assert!(faster < 0.0);
        assert!(slower > 0.0);
    }

    #[test]
    fn read_csv_stats_rejects_missing_column() {
        let path = write_temp_csv("hashes,elapsed_ns\n1,100\n");
        let err = read_csv_stats(&path).expect_err("missing column should fail");
        fs::remove_file(path).ok();
        assert!(err.contains("missing 'ns_per_hash' column"));
    }

    #[test]
    fn read_csv_stats_rejects_empty_csv() {
        let path = write_temp_csv("   \n");
        let err = read_csv_stats(&path).expect_err("empty CSV should fail");
        fs::remove_file(path).ok();
        assert!(err.contains("CSV is empty"));
    }

    #[test]
    fn read_csv_stats_computes_multi_row_mean() {
        let path = write_temp_csv("ns_per_hash,hashes\n100,10\n200,10\n300,10\n");
        let stats = read_csv_stats(&path).expect("valid CSV");
        fs::remove_file(path).ok();
        assert_eq!(stats.rows, 3);
        assert_eq!(stats.min_ns_per_hash, 100.0);
        assert_eq!(stats.max_ns_per_hash, 300.0);
        assert!((stats.mean_ns_per_hash - 200.0).abs() < f64::EPSILON);
    }
}
