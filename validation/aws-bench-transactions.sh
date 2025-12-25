#!/bin/bash
# AWS EC2 transaction benchmark script for StrontiumDB
# Runs the actual transaction benchmarks on cloud infrastructure
# to validate commit-wait performance with real PHC clock sources
#
# Usage: ./aws-bench-transactions.sh [instance-type] [region]

set -e

INSTANCE_TYPE="${1:-m7i.large}"
REGION="${2:-us-east-1}"
KEY_NAME="${3:-strontiumdb-validation}"

echo "═══════════════════════════════════════════════════════════════"
echo "  StrontiumDB Transaction Benchmark on AWS"
echo "  Instance: $INSTANCE_TYPE, Region: $REGION"
echo "═══════════════════════════════════════════════════════════════"

# Get latest Amazon Linux 2023 AMI
echo -e "\n[1/7] Finding latest Amazon Linux 2023 AMI..."
AMI_ID=$(aws ec2 describe-images \
    --region "$REGION" \
    --owners amazon \
    --filters "Name=name,Values=al2023-ami-2023*-x86_64" \
              "Name=state,Values=available" \
    --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
    --output text)
echo "  AMI: $AMI_ID"

# Check for existing key pair
echo -e "\n[2/7] Checking key pair..."
if ! aws ec2 describe-key-pairs --key-names "$KEY_NAME" --region "$REGION" &>/dev/null; then
    echo "  Creating key pair: $KEY_NAME"
    aws ec2 create-key-pair \
        --key-name "$KEY_NAME" \
        --region "$REGION" \
        --query 'KeyMaterial' \
        --output text > "${KEY_NAME}.pem"
    chmod 400 "${KEY_NAME}.pem"
else
    echo "  Key pair exists: $KEY_NAME"
    if [ ! -f "${KEY_NAME}.pem" ]; then
        echo "  ERROR: Key pair exists but ${KEY_NAME}.pem not found locally"
        exit 1
    fi
fi

# Create/get security group
echo -e "\n[3/7] Setting up security group..."
SG_ID=$(aws ec2 describe-security-groups \
    --region "$REGION" \
    --filters "Name=group-name,Values=strontiumdb-validation" \
    --query 'SecurityGroups[0].GroupId' \
    --output text 2>/dev/null || echo "None")

if [ "$SG_ID" = "None" ] || [ -z "$SG_ID" ]; then
    SG_ID=$(aws ec2 create-security-group \
        --group-name strontiumdb-validation \
        --description "StrontiumDB validation" \
        --region "$REGION" \
        --query 'GroupId' \
        --output text)
    aws ec2 authorize-security-group-ingress \
        --group-id "$SG_ID" \
        --protocol tcp \
        --port 22 \
        --cidr 0.0.0.0/0 \
        --region "$REGION"
fi
echo "  Security group: $SG_ID"

# Launch instance
echo -e "\n[4/7] Launching EC2 instance..."
INSTANCE_ID=$(aws ec2 run-instances \
    --image-id "$AMI_ID" \
    --instance-type "$INSTANCE_TYPE" \
    --key-name "$KEY_NAME" \
    --security-group-ids "$SG_ID" \
    --region "$REGION" \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=strontiumdb-txn-bench}]' \
    --query 'Instances[0].InstanceId' \
    --output text)
echo "  Instance ID: $INSTANCE_ID"

cleanup() {
    echo -e "\nCleaning up..."
    aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" --region "$REGION" >/dev/null 2>&1 || true
    echo "  Instance terminated"
}
trap cleanup EXIT

echo "  Waiting for instance to be running..."
aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$REGION"

PUBLIC_IP=$(aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --region "$REGION" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text)
echo "  Public IP: $PUBLIC_IP"

echo "  Waiting for SSH to be ready..."
sleep 30

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Setup PHC
echo -e "\n[5/7] Setting up PHC and build tools..."
ssh -o StrictHostKeyChecking=no -i "${KEY_NAME}.pem" "ec2-user@${PUBLIC_IP}" << 'SETUP_SCRIPT'
set -e
echo "Installing build tools..."
sudo dnf install -y gcc clang clang-devel

echo "Enabling ENA PHC (requires reboot)..."
echo "options ena phc_enable=1" | sudo tee /etc/modprobe.d/ena.conf
echo 'refclock PHC /dev/ptp0 poll 0 delay 0.000010 prefer' | sudo tee -a /etc/chrony.conf
SETUP_SCRIPT

echo "  Rebooting instance to enable PHC..."
aws ec2 reboot-instances --instance-ids "$INSTANCE_ID" --region "$REGION"
sleep 60

echo "  Waiting for SSH after reboot..."
for i in {1..30}; do
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "${KEY_NAME}.pem" "ec2-user@${PUBLIC_IP}" "echo 'SSH ready'" 2>/dev/null; then
        break
    fi
    sleep 5
done

echo "  Waiting for PHC synchronization (2 min)..."
sleep 120

# Verify PHC is working
echo -e "\n[6/7] Verifying PHC setup..."
ssh -o StrictHostKeyChecking=no -i "${KEY_NAME}.pem" "ec2-user@${PUBLIC_IP}" << 'CHECK_SCRIPT'
set -e
echo "PTP devices:"
ls -la /dev/ptp* 2>/dev/null || echo "No /dev/ptp* devices"
for f in /sys/class/ptp/*/clock_name; do [ -f "$f" ] && echo "  $f: $(cat $f)"; done
echo ""
echo "Chrony sources:"
chronyc sources
CHECK_SCRIPT

# Install Rust and upload code
ssh -o StrictHostKeyChecking=no -i "${KEY_NAME}.pem" "ec2-user@${PUBLIC_IP}" << 'RUST_SCRIPT'
set -e
echo "Installing Rust..."
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
mkdir -p strontiumdb
RUST_SCRIPT

echo "  Uploading source code..."
scp -o StrictHostKeyChecking=no -i "${KEY_NAME}.pem" -r \
    "${PROJECT_DIR}/Cargo.toml" \
    "${PROJECT_DIR}/Cargo.lock" \
    "${PROJECT_DIR}/src" \
    "${PROJECT_DIR}/benches" \
    "ec2-user@${PUBLIC_IP}:strontiumdb/"

# Run benchmarks
echo -e "\n[7/7] Running transaction benchmarks..."
ssh -o StrictHostKeyChecking=no -i "${KEY_NAME}.pem" "ec2-user@${PUBLIC_IP}" << 'BENCH_SCRIPT'
set -e
source ~/.cargo/env
cd strontiumdb

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  CLOCK SOURCE VERIFICATION"
echo "═══════════════════════════════════════════════════════════════"
echo ""

cargo build --release --bin validate_timeservice 2>&1 | tail -5
./target/release/validate_timeservice 2>&1 | head -40

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  TRANSACTION BENCHMARKS"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Build benchmarks first
echo "Building benchmarks..."
cargo build --release --bench transactions 2>&1 | tail -5

# Run only the key benchmarks with fewer samples for speed
echo "Running benchmarks..."
cargo bench --bench transactions -- --sample-size 10 "commit_1_key" 2>&1
BENCH_SCRIPT

echo "Benchmark script completed"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Benchmark complete - instance will be terminated"
echo "═══════════════════════════════════════════════════════════════"
