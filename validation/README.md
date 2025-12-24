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
| AWS EC2 (PHC enabled) | `Ntp` (via PHC) | ~5 μs | 100,000x |
| Azure VM | `Ntp` (via PHC) | ~2-20 μs (region-dependent) | 25,000-250,000x |
| GCP | `Ntp` | ~211 μs | 2,400x |

### Azure Multi-Region Results (2025-12-24)

| Region | Uncertainty (p99) |
|--------|------------------|
| West US 2 | 2.3 μs |
| Canada Central | 4.0 μs |
| Norway East | 12.0 μs |
| Sweden Central | 20.2 μs |

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
- [x] Standard_D2s_v3 (canadacentral) - 4.0 μs
- [x] Standard_D2s_v3 (norwayeast) - 12.0 μs
- [x] Standard_D2s_v3 (swedencentral) - 20.2 μs

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
