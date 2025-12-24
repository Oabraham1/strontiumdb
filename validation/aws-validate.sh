#!/bin/bash
# AWS EC2 validation script for StrontiumDB TimeService
# Run from your local machine with AWS CLI configured
#
# Supported PHC instance types: m7i, m7a, m7g, r7i, r7a, r7g, c7i, c7a, c7g
# Note: PHC is NOT enabled by default - this script configures it

set -e

INSTANCE_TYPE="${1:-m7i.large}"
REGION="${2:-us-east-1}"
KEY_NAME="${3:-strontiumdb-validation}"
AMI_ID=""

echo "═══════════════════════════════════════════════════════════════"
echo "  StrontiumDB AWS Validation"
echo "  Instance: $INSTANCE_TYPE, Region: $REGION"
echo "═══════════════════════════════════════════════════════════════"

# Get latest Amazon Linux 2023 AMI
echo -e "\n[1/6] Finding latest Amazon Linux 2023 AMI..."
AMI_ID=$(aws ec2 describe-images \
    --region "$REGION" \
    --owners amazon \
    --filters "Name=name,Values=al2023-ami-2023*-x86_64" \
              "Name=state,Values=available" \
    --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
    --output text)
echo "  AMI: $AMI_ID"

# Create key pair if it doesn't exist
echo -e "\n[2/6] Checking key pair..."
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
fi

# Create security group
echo -e "\n[3/6] Setting up security group..."
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
echo -e "\n[4/6] Launching EC2 instance..."
INSTANCE_ID=$(aws ec2 run-instances \
    --image-id "$AMI_ID" \
    --instance-type "$INSTANCE_TYPE" \
    --key-name "$KEY_NAME" \
    --security-group-ids "$SG_ID" \
    --region "$REGION" \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=strontiumdb-validation}]' \
    --query 'Instances[0].InstanceId' \
    --output text)
echo "  Instance ID: $INSTANCE_ID"

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

echo -e "\n[5/6] Uploading code and running validation..."

ssh -o StrictHostKeyChecking=no -i "${KEY_NAME}.pem" "ec2-user@${PUBLIC_IP}" << 'SETUP_SCRIPT'
set -e
echo "Installing build tools..."
sudo dnf install -y gcc

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

echo "  Waiting for PHC synchronization to stabilize (2 min)..."
sleep 120

ssh -o StrictHostKeyChecking=no -i "${KEY_NAME}.pem" "ec2-user@${PUBLIC_IP}" << 'CHECK_SCRIPT'
set -e
echo "Checking PTP devices after reboot..."
ls -la /dev/ptp* 2>/dev/null || echo "No /dev/ptp* devices"
for f in /sys/class/ptp/*/clock_name; do [ -f "$f" ] && echo "$f: $(cat $f)"; done
echo ""
echo "Chrony sources:"
chronyc sources
CHECK_SCRIPT

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

ssh -o StrictHostKeyChecking=no -i "${KEY_NAME}.pem" "ec2-user@${PUBLIC_IP}" << 'RUN_SCRIPT'
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
aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" --region "$REGION" >/dev/null
echo "  Instance terminated"

echo -e "\n═══════════════════════════════════════════════════════════════"
echo "  Validation complete"
echo "═══════════════════════════════════════════════════════════════"
