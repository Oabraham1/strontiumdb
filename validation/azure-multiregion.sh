#!/bin/bash
# Azure multi-region validation for StrontiumDB TimeService
# Tests Azure PHC availability and uncertainty across geographic regions

VM_SIZE="${1:-Standard_D2s_v3}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="${SCRIPT_DIR}/results"

mkdir -p "$RESULTS_DIR"

# Regions to test - geographically diverse (verified D2s_v3 availability)
REGIONS=(
    "canadacentral"    # Canada
    "swedencentral"    # Europe (Nordic)
    "norwayeast"       # Europe (Norway)
)

echo "═══════════════════════════════════════════════════════════════════════════"
echo "  StrontiumDB Azure Multi-Region Validation"
echo "  VM Size: $VM_SIZE"
echo "  Regions: ${REGIONS[*]}"
echo "═══════════════════════════════════════════════════════════════════════════"

validate_region() {
    local LOCATION="$1"
    local RESOURCE_GROUP="strontiumdb-val-${LOCATION}"
    local VM_NAME="strontiumdb-val"

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Testing region: $LOCATION"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Create resource group
    echo "[1/6] Creating resource group..."
    az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none

    # Create VM with accelerated networking for PTP access
    echo "[2/6] Creating VM with accelerated networking..."
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

    echo "[3/6] Waiting for VM and clock sync (2.5 min)..."
    sleep 150

    # Setup
    echo "[4/6] Installing dependencies..."
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=30 "azureuser@${PUBLIC_IP}" << 'SETUP_SCRIPT'
set -e
sudo apt-get update -qq
sudo apt-get install -qq -y build-essential curl chrony
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
SETUP_SCRIPT

    # Upload code
    echo "[5/6] Uploading source code..."
    ssh -o StrictHostKeyChecking=no "azureuser@${PUBLIC_IP}" "mkdir -p strontiumdb"
    scp -o StrictHostKeyChecking=no -r \
        "${PROJECT_DIR}/Cargo.toml" \
        "${PROJECT_DIR}/Cargo.lock" \
        "${PROJECT_DIR}/src" \
        "${PROJECT_DIR}/benches" \
        "azureuser@${PUBLIC_IP}:strontiumdb/"

    # Build and run
    echo "[6/6] Building and running validation..."
    local RESULT_FILE="${RESULTS_DIR}/azure-${LOCATION}-$(date +%Y-%m-%d).json"

    ssh -o StrictHostKeyChecking=no "azureuser@${PUBLIC_IP}" << 'RUN_SCRIPT' | tee "$RESULT_FILE"
set -e
source ~/.cargo/env
cd strontiumdb
cargo build --release --bin validate_timeservice 2>/dev/null
./target/release/validate_timeservice --json
RUN_SCRIPT

    echo "  Results saved to: $RESULT_FILE"

    # Cleanup
    echo "  Deleting resource group..."
    az group delete --name "$RESOURCE_GROUP" --yes --no-wait
}

# Run validation for each region
for region in "${REGIONS[@]}"; do
    if ! validate_region "$region"; then
        echo "  Warning: Failed to validate $region, continuing with next region..."
        az group delete --name "strontiumdb-val-${region}" --yes --no-wait 2>/dev/null || true
    fi
done

echo ""
echo "═══════════════════════════════════════════════════════════════════════════"
echo "  Multi-Region Validation Complete"
echo "═══════════════════════════════════════════════════════════════════════════"
echo ""
echo "Results saved in: $RESULTS_DIR"
echo ""

# Summary
echo "Summary:"
echo "--------"
for region in "${REGIONS[@]}"; do
    RESULT_FILE="${RESULTS_DIR}/azure-${region}-$(date +%Y-%m-%d).json"
    if [ -f "$RESULT_FILE" ]; then
        P99=$(grep -o '"p99_uncertainty_ns":[0-9]*' "$RESULT_FILE" | cut -d: -f2)
        SOURCE=$(grep -o '"source_type":"[^"]*"' "$RESULT_FILE" | cut -d'"' -f4)
        if [ -n "$P99" ]; then
            P99_US=$(echo "scale=1; $P99/1000" | bc)
            echo "  $region: ${P99_US} μs ($SOURCE)"
        fi
    fi
done
