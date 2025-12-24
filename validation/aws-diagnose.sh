#!/bin/bash
set -e

INSTANCE_TYPE="${1:-c7i.large}"
REGION="${2:-us-east-1}"
KEY_NAME="${3:-strontiumdb-validation}"

echo "═══════════════════════════════════════════════════════════════"
echo "  AWS PHC Diagnostic"
echo "═══════════════════════════════════════════════════════════════"

AMI_ID=$(aws ec2 describe-images \
    --region "$REGION" \
    --owners amazon \
    --filters "Name=name,Values=al2023-ami-2023*-x86_64" \
              "Name=state,Values=available" \
    --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
    --output text)

SG_ID=$(aws ec2 describe-security-groups \
    --region "$REGION" \
    --filters "Name=group-name,Values=strontiumdb-validation" \
    --query 'SecurityGroups[0].GroupId' \
    --output text 2>/dev/null || echo "None")

INSTANCE_ID=$(aws ec2 run-instances \
    --image-id "$AMI_ID" \
    --instance-type "$INSTANCE_TYPE" \
    --key-name "$KEY_NAME" \
    --security-group-ids "$SG_ID" \
    --region "$REGION" \
    --query 'Instances[0].InstanceId' \
    --output text)

echo "Instance: $INSTANCE_ID"
aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$REGION"

PUBLIC_IP=$(aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --region "$REGION" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text)

echo "IP: $PUBLIC_IP"
sleep 30

ssh -o StrictHostKeyChecking=no -i "${KEY_NAME}.pem" "ec2-user@${PUBLIC_IP}" << 'DIAG'
echo "=== PTP Devices ==="
ls -la /dev/ptp* 2>/dev/null || echo "No /dev/ptp* devices found"

echo ""
echo "=== sysfs PTP ==="
ls -la /sys/class/ptp/ 2>/dev/null || echo "No /sys/class/ptp/ found"

for ptp in /sys/class/ptp/ptp*; do
    if [ -d "$ptp" ]; then
        echo ""
        echo "=== $ptp ==="
        cat "$ptp/clock_name" 2>/dev/null && echo "" || echo "No clock_name"
        ls -la "$ptp/device/" 2>/dev/null | head -5 || true
    fi
done

echo ""
echo "=== ENA Driver ==="
modinfo ena 2>/dev/null | head -10 || echo "ENA module info unavailable"

echo ""
echo "=== Instance Metadata ==="
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-type
echo ""

echo ""
echo "=== Chrony Sources ==="
chronyc sources 2>/dev/null || echo "Chronyc not available"
DIAG

aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" --region "$REGION" >/dev/null
echo "Instance terminated"
