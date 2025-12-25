#!/bin/bash
# Azure VM transaction benchmark script for StrontiumDB
# Runs transaction benchmarks on Azure with Hyper-V PTP clock
#
# Usage: ./azure-bench-transactions.sh [vm-size] [location]

set -e

VM_SIZE="${1:-Standard_D4s_v5}"
LOCATION="${2:-eastus}"
RESOURCE_GROUP="strontiumdb-txn-bench"
VM_NAME="strontiumdb-bench"

echo "═══════════════════════════════════════════════════════════════"
echo "  StrontiumDB Transaction Benchmark on Azure"
echo "  VM Size: $VM_SIZE, Location: $LOCATION"
echo "═══════════════════════════════════════════════════════════════"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cleanup() {
    echo -e "\nCleaning up..."
    az group delete --name "$RESOURCE_GROUP" --yes --no-wait 2>/dev/null || true
    echo "  Resource group deletion initiated"
}
trap cleanup EXIT

# Create resource group
echo -e "\n[1/5] Creating resource group..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none
echo "  Resource group: $RESOURCE_GROUP"

# Create VM with accelerated networking
echo -e "\n[2/5] Creating VM with accelerated networking..."
az vm create \
    --resource-group "$RESOURCE_GROUP" \
    --name "$VM_NAME" \
    --image Ubuntu2204 \
    --size "$VM_SIZE" \
    --accelerated-networking true \
    --admin-username azureuser \
    --generate-ssh-keys \
    --output none

PUBLIC_IP=$(az vm show \
    --resource-group "$RESOURCE_GROUP" \
    --name "$VM_NAME" \
    --show-details \
    --query publicIps \
    --output tsv)
echo "  VM created, IP: $PUBLIC_IP"

echo "  Waiting for VM and clock sync (2.5 min)..."
sleep 150

# Setup
echo -e "\n[3/5] Installing dependencies..."
ssh -o StrictHostKeyChecking=no "azureuser@${PUBLIC_IP}" << 'SETUP_SCRIPT'
set -e
echo "Installing build tools..."
sudo apt-get update -qq
sudo apt-get install -qq -y build-essential curl chrony

echo "Installing Rust..."
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

echo ""
echo "PTP devices:"
ls -la /dev/ptp* 2>/dev/null || echo "No /dev/ptp* devices"
for f in /sys/class/ptp/*/clock_name; do [ -f "$f" ] && echo "  $f: $(cat $f)"; done
SETUP_SCRIPT

# Upload code
echo -e "\n[4/5] Uploading source code..."
ssh -o StrictHostKeyChecking=no "azureuser@${PUBLIC_IP}" "mkdir -p strontiumdb"
scp -o StrictHostKeyChecking=no -r \
    "${PROJECT_DIR}/Cargo.toml" \
    "${PROJECT_DIR}/Cargo.lock" \
    "${PROJECT_DIR}/src" \
    "${PROJECT_DIR}/benches" \
    "azureuser@${PUBLIC_IP}:strontiumdb/"

# Build and run benchmarks
echo -e "\n[5/5] Building and running benchmarks..."
ssh -o StrictHostKeyChecking=no "azureuser@${PUBLIC_IP}" << 'BENCH_SCRIPT'
set -e
source ~/.cargo/env
cd strontiumdb

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  CLOCK SOURCE VERIFICATION"
echo "═══════════════════════════════════════════════════════════════"
echo ""

cargo build --release --bin validate_timeservice 2>/dev/null
./target/release/validate_timeservice 2>&1 | head -40

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  TRANSACTION BENCHMARKS"
echo "═══════════════════════════════════════════════════════════════"
echo ""

cargo bench --bench transactions -- --sample-size 20 "begin|commit_1_key|commit_10_keys|lock" 2>&1 | grep -E "(time:|thrpt:|Benchmarking|txn::|lock::)"
BENCH_SCRIPT

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Benchmark complete - VM will be terminated"
echo "═══════════════════════════════════════════════════════════════"
