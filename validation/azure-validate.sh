#!/bin/bash
# Azure VM validation script for StrontiumDB TimeService
# Run from your local machine with Azure CLI configured
#
# Azure VMs with Accelerated Networking have Hyper-V PTP available as /dev/ptp_hyperv

set -e

VM_SIZE="${1:-Standard_D4s_v5}"
LOCATION="${2:-eastus}"
RESOURCE_GROUP="strontiumdb-validation"
VM_NAME="strontiumdb-val"

echo "═══════════════════════════════════════════════════════════════"
echo "  StrontiumDB Azure Validation"
echo "  VM Size: $VM_SIZE, Location: $LOCATION"
echo "═══════════════════════════════════════════════════════════════"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Create resource group
echo -e "\n[1/6] Creating resource group..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none
echo "  Resource group: $RESOURCE_GROUP"

# Create VM with accelerated networking for PTP access
echo -e "\n[2/6] Creating VM with accelerated networking..."
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

echo "  Waiting for VM to be ready..."
sleep 30

echo "  Waiting for clock synchronization to stabilize (2 min)..."
sleep 120

# Setup
echo -e "\n[3/6] Installing dependencies..."
ssh -o StrictHostKeyChecking=no "azureuser@${PUBLIC_IP}" << 'SETUP_SCRIPT'
set -e
echo "Installing build tools..."
sudo apt-get update -qq
sudo apt-get install -qq -y build-essential curl chrony

echo "Installing Rust..."
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

echo ""
echo "Checking PTP devices..."
ls -la /dev/ptp* 2>/dev/null || echo "No /dev/ptp* devices"
ls -la /dev/ptp_hyperv 2>/dev/null || echo "No /dev/ptp_hyperv symlink"

for f in /sys/class/ptp/*/clock_name; do [ -f "$f" ] && echo "$f: $(cat $f)"; done

echo ""
echo "Chrony sources:"
chronyc sources 2>/dev/null || echo "Chrony not running"
SETUP_SCRIPT

# Upload code
echo -e "\n[4/6] Uploading source code..."
ssh -o StrictHostKeyChecking=no "azureuser@${PUBLIC_IP}" "mkdir -p strontiumdb"
scp -o StrictHostKeyChecking=no -r \
    "${PROJECT_DIR}/Cargo.toml" \
    "${PROJECT_DIR}/Cargo.lock" \
    "${PROJECT_DIR}/src" \
    "${PROJECT_DIR}/benches" \
    "azureuser@${PUBLIC_IP}:strontiumdb/"

# Build and run
echo -e "\n[5/6] Building and running validation..."
ssh -o StrictHostKeyChecking=no "azureuser@${PUBLIC_IP}" << 'RUN_SCRIPT'
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
RUN_SCRIPT

# Cleanup
echo -e "\n[6/6] Cleaning up..."
az group delete --name "$RESOURCE_GROUP" --yes --no-wait
echo "  Resource group deletion initiated"

echo -e "\n═══════════════════════════════════════════════════════════════"
echo "  Validation complete"
echo "═══════════════════════════════════════════════════════════════"
