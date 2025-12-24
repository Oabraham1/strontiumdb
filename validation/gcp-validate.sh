#!/bin/bash
# GCP Compute Engine validation script for StrontiumDB TimeService
# Run from your local machine with gcloud CLI configured
#
# GCP does not expose PTP to VMs - will use NTP via chrony

set -e

MACHINE_TYPE="${1:-n2-standard-4}"
ZONE="${2:-us-central1-a}"
INSTANCE_NAME="strontiumdb-validation"
PROJECT=$(gcloud config get-value project)

echo "═══════════════════════════════════════════════════════════════"
echo "  StrontiumDB GCP Validation"
echo "  Machine: $MACHINE_TYPE, Zone: $ZONE"
echo "  Project: $PROJECT"
echo "═══════════════════════════════════════════════════════════════"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Create instance
echo -e "\n[1/5] Creating Compute Engine instance..."
gcloud compute instances create "$INSTANCE_NAME" \
    --zone="$ZONE" \
    --machine-type="$MACHINE_TYPE" \
    --image-family=ubuntu-2204-lts \
    --image-project=ubuntu-os-cloud \
    --boot-disk-size=20GB \
    --quiet

echo "  Waiting for instance to be ready..."
sleep 30

echo "  Waiting for clock synchronization to stabilize (2 min)..."
sleep 120

# Setup
echo -e "\n[2/5] Installing dependencies..."
gcloud compute ssh "$INSTANCE_NAME" --zone="$ZONE" --command='
set -e
echo "Installing build tools..."
sudo apt-get update -qq
sudo apt-get install -qq -y build-essential curl chrony

echo "Installing Rust..."
curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

echo ""
echo "Checking PTP devices..."
ls -la /dev/ptp* 2>/dev/null || echo "No /dev/ptp* devices (expected on GCP)"

echo ""
echo "Chrony sources:"
chronyc sources 2>/dev/null || echo "Chrony not running"

echo ""
echo "Chrony tracking:"
chronyc tracking 2>/dev/null || echo "Chrony not running"
'

# Upload code
echo -e "\n[3/5] Uploading source code..."
gcloud compute ssh "$INSTANCE_NAME" --zone="$ZONE" --command="mkdir -p strontiumdb"
gcloud compute scp --zone="$ZONE" --recurse \
    "${PROJECT_DIR}/Cargo.toml" \
    "${PROJECT_DIR}/Cargo.lock" \
    "${PROJECT_DIR}/src" \
    "${PROJECT_DIR}/benches" \
    "${INSTANCE_NAME}:strontiumdb/"

# Build and run
echo -e "\n[4/5] Building and running validation..."
gcloud compute ssh "$INSTANCE_NAME" --zone="$ZONE" --command='
set -e
source ~/.cargo/env
cd strontiumdb

echo "Building validation binary..."
cargo build --release --bin validate_timeservice

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  VALIDATION RESULTS"
echo "═══════════════════════════════════════════════════════════════"
echo ""
./target/release/validate_timeservice --json
'

# Cleanup
echo -e "\n[5/5] Cleaning up..."
gcloud compute instances delete "$INSTANCE_NAME" --zone="$ZONE" --quiet
echo "  Instance deleted"

echo -e "\n═══════════════════════════════════════════════════════════════"
echo "  Validation complete"
echo "═══════════════════════════════════════════════════════════════"
