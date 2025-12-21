# StrontiumDB Cloud Validation

Scripts to validate TimeService clock detection and uncertainty measurement across cloud providers.

## Prerequisites

- Rust toolchain (for local build verification)
- Cloud CLI tools configured:
  - AWS: `aws configure`
  - Azure: `az login`
  - GCP: `gcloud auth login`

## Quick Start

```bash
# Make scripts executable
chmod +x *.sh

# AWS (requires ~8 min, ~$0.05)
./aws-validate.sh m7i.large us-east-1

# Azure (requires ~8 min, ~$0.05)
./azure-validate.sh Standard_D2s_v3 westus2

# GCP (requires ~8 min, ~$0.05)
./gcp-validate.sh n2-standard-4 us-central1-a
```

## What Gets Validated

1. **Clock Source Detection** - Verifies automatic detection of:
   - AWS: ENA PHC (`/dev/ptp*` with `ena` clock name)
   - Azure: Hyper-V PHC (`/dev/ptp_hyperv`)
   - GCP: NTP fallback (no PHC available)

2. **Uncertainty Measurement** - Samples 1000 timestamps to measure:
   - Min/P50/P99/Max uncertainty bounds
   - Compares against paper claims

3. **API Performance** - Benchmarks:
   - `now()` latency (target: <100ns)
   - `uncertainty_bound()` latency (target: <10ns)

4. **Monotonicity** - Verifies timestamps are strictly increasing

## Validated Results

| Cloud | Source | Uncertainty | Improvement vs 500ms |
|-------|--------|-------------|---------------------|
| AWS EC2 (PHC enabled) | `Ntp` (via PHC) | ~5 μs | 50,000x |
| Azure VM | `Ntp` (via PHC) | ~2.3 μs | 217,000x |
| GCP | `Ntp` | ~211 μs | 2,400x |

## Manual Validation

If you prefer to run manually:

```bash
# Build locally first
cargo build --release --bin validate_timeservice

# Then on the cloud instance:
git clone https://github.com/strontiumdb/strontiumdb.git
cd strontiumdb
cargo build --release --bin validate_timeservice
./target/release/validate_timeservice
```

## Instance Types Tested

### AWS
- [x] m7i.large (us-east-1) - 5 μs with PHC enabled

### Azure
- [x] Standard_D2s_v3 (westus2) - 2.3 μs

### GCP
- [x] n2-standard-4 (us-central1-a) - 211 μs

## Cleanup

All scripts prompt before deleting resources. If you need to clean up manually:

```bash
# AWS
aws ec2 terminate-instances --instance-ids <id>

# Azure
az group delete --name strontiumdb-validation

# GCP
gcloud compute instances delete strontiumdb-validation --zone=<zone>
```
