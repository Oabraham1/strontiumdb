// Copyright 2025 Ojima Abraham
// SPDX-License-Identifier: Apache-2.0

//! Cloud validation binary for TimeService.
//!
//! Run this on AWS, Azure, GCP, and on-prem to verify clock source detection
//! and measure actual uncertainty bounds.
//!
//! Usage:
//!   ./validate_timeservice          # Human-readable output
//!   ./validate_timeservice --json   # JSON output for paper evidence

use std::time::{Duration, Instant};
use strontiumdb::time::{create_time_service, ClockSource, TimeService};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let json_mode = args.iter().any(|a| a == "--json");

    if json_mode {
        run_json_validation();
    } else {
        run_human_validation();
    }
}

fn run_json_validation() {
    let service = create_time_service();
    let cloud = detect_cloud();
    let instance_type = get_instance_type(&cloud);
    let region = get_region(&cloud);
    let source = service.source_type();
    let uncertainty = service.uncertainty_bound();

    let (phc_device, clock_name) = get_phc_info();
    let phc_error_bound = get_phc_error_bound();

    let (uncertainty_min, uncertainty_p50, uncertainty_p99, uncertainty_max) =
        measure_uncertainty_stats(&*service);
    let (now_p50, now_p99) = benchmark_now(&*service);
    let monotonic = check_monotonicity(&*service);

    let timestamp = chrono_timestamp();

    println!("{{");
    println!("  \"cloud\": \"{}\",", cloud);
    println!("  \"instance_type\": \"{}\",", instance_type);
    println!("  \"region\": \"{}\",", region);
    println!("  \"detected_source\": \"{:?}\",", source);
    println!("  \"phc_device\": {},", json_string_or_null(&phc_device));
    println!("  \"clock_name\": {},", json_string_or_null(&clock_name));
    println!(
        "  \"phc_error_bound_ns\": {},",
        phc_error_bound
            .map(|v| v.to_string())
            .unwrap_or("null".to_string())
    );
    println!("  \"reported_uncertainty_ns\": {},", uncertainty.as_nanos());
    println!("  \"measured_uncertainty_min_ns\": {},", uncertainty_min);
    println!("  \"measured_uncertainty_p50_ns\": {},", uncertainty_p50);
    println!("  \"measured_uncertainty_p99_ns\": {},", uncertainty_p99);
    println!("  \"measured_uncertainty_max_ns\": {},", uncertainty_max);
    println!("  \"now_latency_p50_ns\": {:.1},", now_p50);
    println!("  \"now_latency_p99_ns\": {:.1},", now_p99);
    println!("  \"monotonicity_verified\": {},", monotonic);
    println!("  \"timestamp\": \"{}\"", timestamp);
    println!("}}");
}

fn json_string_or_null(s: &Option<String>) -> String {
    match s {
        Some(v) => format!("\"{}\"", v),
        None => "null".to_string(),
    }
}

fn chrono_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let secs = duration.as_secs();
    format!("{}", secs)
}

fn detect_cloud() -> String {
    if check_gcp_metadata() {
        return "gcp".to_string();
    }
    if check_azure_metadata() {
        return "azure".to_string();
    }
    if check_aws_metadata() {
        return "aws".to_string();
    }
    "unknown".to_string()
}

fn get_instance_type(cloud: &str) -> String {
    match cloud {
        "aws" => {
            let token = get_aws_imds_token();
            let mut cmd = std::process::Command::new("curl");
            cmd.args(["-s", "-m", "1"]);
            if let Some(ref t) = token {
                cmd.args(["-H", &format!("X-aws-ec2-metadata-token: {}", t)]);
            }
            cmd.arg("http://169.254.169.254/latest/meta-data/instance-type");
            cmd.output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .filter(|s| !s.contains("Error") && !s.contains("<?xml"))
                .unwrap_or_else(|| "unknown".to_string())
        }
        "azure" => std::process::Command::new("curl")
            .args(["-s", "-m", "1", "-H", "Metadata:true",
                   "http://169.254.169.254/metadata/instance/compute/vmSize?api-version=2021-02-01&format=text"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .filter(|s| !s.is_empty() && !s.contains("Error"))
            .unwrap_or_else(|| "unknown".to_string()),
        "gcp" => std::process::Command::new("curl")
            .args(["-s", "-m", "1", "-H", "Metadata-Flavor: Google",
                   "http://metadata.google.internal/computeMetadata/v1/instance/machine-type"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .filter(|s| !s.contains("Error") && !s.contains("<!DOCTYPE"))
            .map(|s| s.split('/').next_back().unwrap_or("unknown").to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        _ => "unknown".to_string(),
    }
}

fn get_region(cloud: &str) -> String {
    match cloud {
        "aws" => {
            let token = get_aws_imds_token();
            let mut cmd = std::process::Command::new("curl");
            cmd.args(["-s", "-m", "1"]);
            if let Some(ref t) = token {
                cmd.args(["-H", &format!("X-aws-ec2-metadata-token: {}", t)]);
            }
            cmd.arg("http://169.254.169.254/latest/meta-data/placement/availability-zone");
            cmd.output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .filter(|s| !s.contains("Error") && !s.contains("<?xml"))
                .unwrap_or_else(|| "unknown".to_string())
        }
        "azure" => std::process::Command::new("curl")
            .args(["-s", "-m", "1", "-H", "Metadata:true",
                   "http://169.254.169.254/metadata/instance/compute/location?api-version=2021-02-01&format=text"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .filter(|s| !s.is_empty() && !s.contains("Error"))
            .unwrap_or_else(|| "unknown".to_string()),
        "gcp" => std::process::Command::new("curl")
            .args(["-s", "-m", "1", "-H", "Metadata-Flavor: Google",
                   "http://metadata.google.internal/computeMetadata/v1/instance/zone"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .filter(|s| !s.contains("Error") && !s.contains("<!DOCTYPE"))
            .map(|s| s.split('/').next_back().unwrap_or("unknown").to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        _ => "unknown".to_string(),
    }
}

fn get_phc_info() -> (Option<String>, Option<String>) {
    for i in 0..8 {
        let path = format!("/dev/ptp{}", i);
        if std::path::Path::new(&path).exists() {
            let name_path = format!("/sys/class/ptp/ptp{}/clock_name", i);
            let name = std::fs::read_to_string(&name_path)
                .map(|s| s.trim().to_string())
                .ok();
            return (Some(path), name);
        }
    }
    (None, None)
}

fn get_phc_error_bound() -> Option<u64> {
    let paths = [
        "/sys/class/ptp/ptp0/device/phc_error_bound",
        "/sys/devices/pci0000:00/0000:00:05.0/phc_error_bound",
    ];
    for path in paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(micros) = content.trim().parse::<u64>() {
                return Some(micros * 1000);
            }
        }
    }
    None
}

fn measure_uncertainty_stats(service: &dyn TimeService) -> (u64, u64, u64, u64) {
    const SAMPLES: usize = 1000;
    let mut uncertainties = Vec::with_capacity(SAMPLES);

    for _ in 0..SAMPLES {
        let ts = service.now();
        uncertainties.push(ts.latest() - ts.earliest());
        std::thread::sleep(Duration::from_millis(1));
    }

    uncertainties.sort();
    (
        uncertainties[0],
        uncertainties[SAMPLES / 2],
        uncertainties[SAMPLES * 99 / 100],
        uncertainties[SAMPLES - 1],
    )
}

fn benchmark_now(service: &dyn TimeService) -> (f64, f64) {
    const ITERATIONS: usize = 100_000;
    let mut latencies = Vec::with_capacity(ITERATIONS);

    for _ in 0..ITERATIONS {
        let start = Instant::now();
        std::hint::black_box(service.now());
        latencies.push(start.elapsed().as_nanos() as f64);
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (latencies[ITERATIONS / 2], latencies[ITERATIONS * 99 / 100])
}

fn check_monotonicity(service: &dyn TimeService) -> bool {
    const ITERATIONS: usize = 100_000;
    let mut prev = service.now();

    for _ in 0..ITERATIONS {
        let curr = service.now();
        if curr.midpoint() < prev.midpoint() {
            return false;
        }
        prev = curr;
    }
    true
}

fn run_human_validation() {
    println!("═══════════════════════════════════════════════════════════════");
    println!("  StrontiumDB TimeService Cloud Validation");
    println!("═══════════════════════════════════════════════════════════════\n");

    print_system_info();

    let service = create_time_service();

    println!("── Clock Source Detection ──────────────────────────────────────\n");
    print_detection_results(&*service);

    println!("\n── Uncertainty Measurement ─────────────────────────────────────\n");
    measure_uncertainty(&*service);

    println!("\n── API Performance ─────────────────────────────────────────────\n");
    benchmark_api(&*service);

    println!("\n── Monotonicity Verification ───────────────────────────────────\n");
    verify_monotonicity(&*service);

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  Validation Complete");
    println!("═══════════════════════════════════════════════════════════════");
}

fn print_system_info() {
    println!("── System Information ──────────────────────────────────────────\n");

    if let Ok(hostname) = std::fs::read_to_string("/etc/hostname") {
        println!("  Hostname: {}", hostname.trim());
    }

    if let Ok(release) = std::fs::read_to_string("/etc/os-release") {
        for line in release.lines() {
            if line.starts_with("PRETTY_NAME=") {
                let name = line.trim_start_matches("PRETTY_NAME=").trim_matches('"');
                println!("  OS: {}", name);
                break;
            }
        }
    }

    if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in cpuinfo.lines() {
            if line.starts_with("model name") {
                if let Some(model) = line.split(':').nth(1) {
                    println!("  CPU: {}", model.trim());
                    break;
                }
            }
        }
    }

    print_cloud_metadata();
    println!();
}

fn print_cloud_metadata() {
    if check_gcp_metadata() {
        println!("  Cloud: GCP");
        return;
    }

    if check_azure_metadata() {
        println!("  Cloud: Azure");
        return;
    }

    if check_aws_metadata() {
        println!("  Cloud: AWS EC2");
        return;
    }

    println!("  Cloud: Unknown/On-premises");
}

fn get_aws_imds_token() -> Option<String> {
    std::process::Command::new("curl")
        .args([
            "-s",
            "-m",
            "1",
            "-X",
            "PUT",
            "-H",
            "X-aws-ec2-metadata-token-ttl-seconds: 60",
            "http://169.254.169.254/latest/api/token",
        ])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .filter(|s| !s.is_empty() && !s.contains("<?xml") && !s.contains("Error"))
}

fn check_aws_metadata() -> bool {
    if let Some(token) = get_aws_imds_token() {
        std::process::Command::new("curl")
            .args([
                "-s",
                "-m",
                "1",
                "-H",
                &format!("X-aws-ec2-metadata-token: {}", token),
                "http://169.254.169.254/latest/meta-data/instance-type",
            ])
            .output()
            .map(|o| o.status.success() && !o.stdout.is_empty())
            .unwrap_or(false)
    } else {
        std::process::Command::new("curl")
            .args([
                "-s",
                "-m",
                "1",
                "http://169.254.169.254/latest/meta-data/instance-type",
            ])
            .output()
            .map(|o| o.status.success() && !o.stdout.is_empty())
            .unwrap_or(false)
    }
}

fn check_azure_metadata() -> bool {
    std::process::Command::new("curl")
        .args([
            "-s",
            "-m",
            "1",
            "-H",
            "Metadata:true",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        ])
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
}

fn check_gcp_metadata() -> bool {
    std::process::Command::new("curl")
        .args([
            "-s",
            "-m",
            "1",
            "-H",
            "Metadata-Flavor: Google",
            "http://metadata.google.internal/computeMetadata/v1/instance/zone",
        ])
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
}

fn print_detection_results(service: &dyn TimeService) {
    let source = service.source_type();
    let uncertainty = service.uncertainty_bound();

    println!("  Detected source: {:?}", source);
    println!("  Uncertainty bound: {:?}", uncertainty);

    match source {
        ClockSource::Gps => {
            println!("  ✓ GPS/PPS device detected");
            print_pps_devices();
        }
        ClockSource::AwsPhc => {
            println!("  ✓ AWS ENA PHC detected");
            print_ptp_devices();
            print_phc_error_bound();
        }
        ClockSource::AzurePhc => {
            println!("  ✓ Azure Hyper-V PHC detected");
            print_ptp_devices();
        }
        ClockSource::GcpPhc => {
            println!("  ✓ GCP PHC detected");
            print_ptp_devices();
        }
        ClockSource::PtpHardware => {
            println!("  ✓ PTP hardware timestamping detected");
            print_ptp_devices();
        }
        ClockSource::PtpSoftware => {
            println!("  ⚠ PTP software timestamping (no hardware support)");
            print_ptp_devices();
        }
        ClockSource::Ntp => {
            println!("  ⚠ NTP fallback");
            print_chrony_status();
        }
        ClockSource::Hlc => {
            println!("  ⚠ HLC fallback (no precision time source)");
        }
    }
}

fn print_pps_devices() {
    println!("\n  PPS devices:");
    for i in 0..4 {
        let path = format!("/dev/pps{}", i);
        if std::path::Path::new(&path).exists() {
            let name_path = format!("/sys/class/pps/pps{}/name", i);
            let name = std::fs::read_to_string(&name_path)
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            println!("    /dev/pps{}: {}", i, name);
        }
    }
}

fn print_ptp_devices() {
    println!("\n  PTP devices:");
    for i in 0..8 {
        let path = format!("/dev/ptp{}", i);
        if std::path::Path::new(&path).exists() {
            let name_path = format!("/sys/class/ptp/ptp{}/clock_name", i);
            let name = std::fs::read_to_string(&name_path)
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            println!("    /dev/ptp{}: {}", i, name);
        }
    }

    if std::path::Path::new("/dev/ptp_hyperv").exists() {
        println!("    /dev/ptp_hyperv (Azure symlink)");
    }
}

fn print_phc_error_bound() {
    let paths = [
        "/sys/class/ptp/ptp0/device/phc_error_bound",
        "/sys/devices/pci0000:00/0000:00:05.0/phc_error_bound",
    ];

    for path in paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            println!("\n  PHC error bound ({}): {} μs", path, content.trim());
            return;
        }
    }
    println!("\n  PHC error bound: not available via sysfs");
}

fn print_chrony_status() {
    println!("\n  Chrony tracking:");
    if let Ok(output) = std::process::Command::new("chronyc")
        .arg("tracking")
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("System time")
                    || line.contains("Root dispersion")
                    || line.contains("Stratum")
                {
                    println!("    {}", line.trim());
                }
            }
        }
    } else {
        println!("    chronyc not available");
    }
}

fn measure_uncertainty(service: &dyn TimeService) {
    const SAMPLES: usize = 1000;
    let mut uncertainties = Vec::with_capacity(SAMPLES);

    for _ in 0..SAMPLES {
        let ts = service.now();
        uncertainties.push(ts.latest() - ts.earliest());
        std::thread::sleep(Duration::from_millis(1));
    }

    uncertainties.sort();

    let min = uncertainties[0];
    let p50 = uncertainties[SAMPLES / 2];
    let p99 = uncertainties[SAMPLES * 99 / 100];
    let max = uncertainties[SAMPLES - 1];

    println!("  Sampled {} timestamps over ~1 second:\n", SAMPLES);
    println!(
        "    Min uncertainty:  {:>10} ns  ({:.2} μs)",
        min,
        min as f64 / 1000.0
    );
    println!(
        "    P50 uncertainty:  {:>10} ns  ({:.2} μs)",
        p50,
        p50 as f64 / 1000.0
    );
    println!(
        "    P99 uncertainty:  {:>10} ns  ({:.2} μs)",
        p99,
        p99 as f64 / 1000.0
    );
    println!(
        "    Max uncertainty:  {:>10} ns  ({:.2} μs)",
        max,
        max as f64 / 1000.0
    );
}

fn benchmark_api(service: &dyn TimeService) {
    const ITERATIONS: u64 = 1_000_000;

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        std::hint::black_box(service.now());
    }
    let elapsed = start.elapsed();
    let ns_per_call = elapsed.as_nanos() as f64 / ITERATIONS as f64;

    println!("  now() latency ({} iterations):", ITERATIONS);
    println!("    Average: {:.2} ns", ns_per_call);

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        std::hint::black_box(service.uncertainty_bound());
    }
    let elapsed = start.elapsed();
    let ns_per_call = elapsed.as_nanos() as f64 / ITERATIONS as f64;

    println!(
        "\n  uncertainty_bound() latency ({} iterations):",
        ITERATIONS
    );
    println!("    Average: {:.2} ns", ns_per_call);
}

fn verify_monotonicity(service: &dyn TimeService) {
    const ITERATIONS: usize = 100_000;
    let mut violations = 0;
    let mut prev = service.now();

    for _ in 0..ITERATIONS {
        let curr = service.now();
        if curr.midpoint() < prev.midpoint() {
            violations += 1;
        }
        prev = curr;
    }

    println!("  Checked {} consecutive timestamps:", ITERATIONS);
    if violations == 0 {
        println!("    ✓ No monotonicity violations");
    } else {
        println!("    ✗ {} monotonicity violations detected!", violations);
    }
}
