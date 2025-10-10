#!/bin/bash

# Description and Criteria
description="AWS Audit for Backend EC2 Instance Public Subnet Exposure"
criteria="This script checks if backend EC2 instances are running in a public subnet by verifying the associated VPC route tables.
Instances using public subnets are marked as 'Non-Compliant'."

# Command being used
command_used="Commands Used:
  1. aws ec2 describe-regions --query 'Regions[*].RegionName' --output text
  2. aws ec2 describe-instances --region \$REGION --query 'Reservations[*].Instances[*].InstanceId'
  3. aws ec2 describe-instances --region \$REGION --instance-ids \$INSTANCE_ID --query 'Reservations[*].Instances[*].SubnetId'
  4. aws ec2 describe-route-tables --region \$REGION --filters \"Name=association.subnet-id,Values=\$SUBNET_ID\" --query 'RouteTables[*].Routes[]'"

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
NC='\033[0m'  # No color

# Display script metadata
echo ""
echo "---------------------------------------------------------------------"
echo -e "${PURPLE}Description: $description${NC}"
echo ""
echo -e "${PURPLE}Criteria: $criteria${NC}"
echo ""
echo -e "${PURPLE}$command_used${NC}"
echo "---------------------------------------------------------------------"
echo ""

# Set AWS CLI profile
PROFILE="my-role"

# Validate if the profile exists
if ! aws configure list-profiles | grep -q "^$PROFILE$"; then
  echo "ERROR: AWS profile '$PROFILE' does not exist."
  exit 1
fi

# Get list of all AWS regions
regions=$(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text --profile "$PROFILE")

# Table Header
echo "\n+----------------+----------------+"
echo "| Region         | Instances Found |"
echo "+----------------+----------------+"

# Audit each region
declare -A region_instance_count
for REGION in $regions; do
  instances=$(aws ec2 describe-instances --region "$REGION" --profile "$PROFILE" \
    --query 'Reservations[*].Instances[*].InstanceId' --output text)

  instance_count=$(echo "$instances" | wc -w)
  region_instance_count[$REGION]=$instance_count

  printf "| %-14s | %-14s |\n" "$REGION" "$instance_count"
done
echo "+----------------+----------------+"
echo ""

# Audit each instance to check if it's in a public subnet
for REGION in "${!region_instance_count[@]}"; do
  if [ "${region_instance_count[$REGION]}" -gt 0 ]; then
    echo -e "${PURPLE}Starting audit for region: $REGION${NC}"

    for INSTANCE_ID in $(aws ec2 describe-instances --region "$REGION" --profile "$PROFILE" \
      --query 'Reservations[*].Instances[*].InstanceId' --output text); do
      
      # Get the subnet ID for the instance
      SUBNET_ID=$(aws ec2 describe-instances --region "$REGION" --profile "$PROFILE" \
        --instance-ids "$INSTANCE_ID" --query 'Reservations[*].Instances[*].SubnetId' --output text)

      # Get route table details for the subnet
      ROUTE_INFO=$(aws ec2 describe-route-tables --region "$REGION" --profile "$PROFILE" \
        --filters "Name=association.subnet-id,Values=$SUBNET_ID" --query 'RouteTables[*].Routes[]' --output json)

      # Check if instance is in a public subnet (has IGW route)
      if echo "$ROUTE_INFO" | grep -q '"GatewayId": "igw-'; then
        STATUS="${RED}Non-Compliant (Instance in Public Subnet)${NC}"
      else
        STATUS="${GREEN}Compliant (Instance in Private Subnet)${NC}"
      fi

      # Print audit details
      echo "--------------------------------------------------"
      echo "Region: $REGION"
      echo "Instance ID: $INSTANCE_ID"
      echo "Subnet ID: $SUBNET_ID"
      echo "Status: $STATUS"
      echo "--------------------------------------------------"
    done
  fi
done

echo "Audit completed for all regions."
