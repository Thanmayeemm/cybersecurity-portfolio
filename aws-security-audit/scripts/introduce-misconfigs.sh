#!/usr/bin/env bash
#
# WARNING - FOR AUDIT LAB USE ONLY.
# Do not run against production accounts. This script intentionally weakens
# security controls to generate CIS AWS Foundations Benchmark v2.0.0 findings.
#
set -euo pipefail

# --- Lab configuration (change these) ---
BUCKET_NAME="${BUCKET_NAME:-}"
REGION="${REGION:-}"
SG_NAME="${SG_NAME:-}"
IAM_USER_NAME="${IAM_USER_NAME:-cis-lab-admin-user}"
TRAIL_NAME="${TRAIL_NAME:-cis-lab-single-region-trail}"
# Derived: dedicated bucket for CloudTrail logs (separate from the public S3 finding bucket)
CLOUDTRAIL_LOG_BUCKET="${CLOUDTRAIL_LOG_BUCKET:-}"

require_vars() {
  if [[ -z "${BUCKET_NAME}" ]]; then
    printf '%s\n' "ERROR: Set BUCKET_NAME to a globally unique S3 bucket name." >&2
    exit 1
  fi
  if [[ -z "${REGION}" ]]; then
    printf '%s\n' "ERROR: Set REGION (for example: us-east-1)." >&2
    exit 1
  fi
  if [[ -z "${SG_NAME}" ]]; then
    printf '%s\n' "ERROR: Set SG_NAME (EC2 security group name)." >&2
    exit 1
  fi
  if [[ -z "${CLOUDTRAIL_LOG_BUCKET}" ]]; then
    CLOUDTRAIL_LOG_BUCKET="${BUCKET_NAME}-cloudtrail-logs"
  fi
}

aws_cli() {
  aws --region "${REGION}" "$@"
}

bucket_exists() {
  local name="$1"
  aws_cli s3api head-bucket --bucket "${name}" 2>/dev/null
}

create_bucket_if_missing() {
  local name="$1"
  if bucket_exists "${name}"; then
    return 0
  fi
  if [[ "${REGION}" == "us-east-1" ]]; then
    aws_cli s3api create-bucket --bucket "${name}" # CIS 2.1.1 - lab misconfiguration (public exposure setup)
  else
    aws_cli s3api create-bucket \
      --bucket "${name}" \
      --create-bucket-configuration "LocationConstraint=${REGION}" # CIS 2.1.1 - lab misconfiguration (public exposure setup)
  fi
}

put_public_bucket_misconfiguration() {
  create_bucket_if_missing "${BUCKET_NAME}"

  # Disable Block Public Access at bucket level (all four settings off)
  aws_cli s3api put-public-access-block \
    --bucket "${BUCKET_NAME}" \
    --public-access-block-configuration "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false" # CIS 2.1.1 - Block Public Access disabled

  local policy
  policy="$(printf '%s\n' "{
  \"Version\": \"2012-10-17\",
  \"Statement\": [
    {
      \"Sid\": \"PublicReadLab\",
      \"Effect\": \"Allow\",
      \"Principal\": \"*\",
      \"Action\": [\"s3:GetObject\"],
      \"Resource\": \"arn:aws:s3:::%s/*\"
    }
  ]
}" "${BUCKET_NAME}")"

  aws_cli s3api put-bucket-policy --bucket "${BUCKET_NAME}" --policy "${policy}" # CIS 2.1.1 - public bucket policy (anonymous read)

  # Optional evidence object (idempotent overwrite)
  printf '%s\n' "cis-lab-public-read-object" | aws_cli s3 cp - "s3://${BUCKET_NAME}/cis-lab-evidence.txt" || true
}

ensure_iam_user_with_admin_policy() {
  if ! aws iam get-user --user-name "${IAM_USER_NAME}" >/dev/null 2>&1; then
    aws iam create-user --user-name "${IAM_USER_NAME}" # CIS 1.16 - direct-to-user attachment pattern (lab)
  fi

  local attached
  # shellcheck disable=SC2016
  attached="$(aws iam list-attached-user-policies --user-name "${IAM_USER_NAME}" --query 'AttachedPolicies[?PolicyArn==`arn:aws:iam::aws:policy/AdministratorAccess`] | length(@)' --output text)"
  if [[ "${attached}" == "0" ]]; then
    aws iam attach-user-policy --user-name "${IAM_USER_NAME}" --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess" # CIS 1.16 - AdministratorAccess attached directly to IAM user
  fi
}

put_cloudtrail_bucket_policy() {
  local bucket="$1"
  local account_id="$2"
  local policy
  policy="$(printf '%s\n' "{
  \"Version\": \"2012-10-17\",
  \"Statement\": [
    {
      \"Sid\": \"AWSCloudTrailAclCheck\",
      \"Effect\": \"Allow\",
      \"Principal\": {\"Service\": \"cloudtrail.amazonaws.com\"},
      \"Action\": \"s3:GetBucketAcl\",
      \"Resource\": \"arn:aws:s3:::%s\"
    },
    {
      \"Sid\": \"AWSCloudTrailWrite\",
      \"Effect\": \"Allow\",
      \"Principal\": {\"Service\": \"cloudtrail.amazonaws.com\"},
      \"Action\": \"s3:PutObject\",
      \"Resource\": \"arn:aws:s3:::%s/AWSLogs/%s/*\",
      \"Condition\": {
        \"StringEquals\": {
          \"s3:x-amz-acl\": \"bucket-owner-full-control\"
        }
      }
    }
  ]
}" "${bucket}" "${bucket}" "${account_id}")"

  aws_cli s3api put-bucket-policy --bucket "${bucket}" --policy "${policy}"
}

ensure_single_region_trail() {
  local account_id="$1"

  create_bucket_if_missing "${CLOUDTRAIL_LOG_BUCKET}"
  put_cloudtrail_bucket_policy "${CLOUDTRAIL_LOG_BUCKET}" "${account_id}"

  local trail_count
  trail_count="$(aws_cli cloudtrail describe-trails --trail-name-list "${TRAIL_NAME}" --query 'length(trailList)' --output text)"

  if [[ "${trail_count}" == "0" ]]; then
    aws_cli cloudtrail create-trail \
      --name "${TRAIL_NAME}" \
      --s3-bucket-name "${CLOUDTRAIL_LOG_BUCKET}" \
      --no-is-multi-region-trail # CIS 3.1 - CloudTrail not enabled for all regions (single-region trail)
  else
    aws_cli cloudtrail update-trail \
      --name "${TRAIL_NAME}" \
      --no-is-multi-region-trail # CIS 3.1 - keep misconfiguration idempotently
  fi

  aws_cli cloudtrail start-logging --name "${TRAIL_NAME}"
}

ensure_ssh_open_to_world_sg() {
  local vpc_id
  vpc_id="$(aws_cli ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
  if [[ -z "${vpc_id}" || "${vpc_id}" == "None" ]]; then
    printf '%s\n' "ERROR: No default VPC found in ${REGION}. Create a VPC or choose a region with a default VPC." >&2
    exit 1
  fi

  local sg_id
  sg_id="$(aws_cli ec2 describe-security-groups --filters "Name=group-name,Values=${SG_NAME}" "Name=vpc-id,Values=${vpc_id}" --query 'SecurityGroups[0].GroupId' --output text)"
  if [[ -z "${sg_id}" || "${sg_id}" == "None" ]]; then
    sg_id="$(aws_cli ec2 create-security-group --group-name "${SG_NAME}" --description "CIS lab SG (intentionally insecure)" --vpc-id "${vpc_id}" --query 'GroupId' --output text)" # CIS 5.2 - SSH exposure setup
  fi

  local open_ssh
  # shellcheck disable=SC2016
  open_ssh="$(aws_cli ec2 describe-security-groups --group-ids "${sg_id}" --query 'SecurityGroups[0].IpPermissions[?FromPort==`22` && ToPort==`22` && IpProtocol==`tcp`].IpRanges[?CidrIp==`0.0.0.0/0`].CidrIp' --output text)"
  if [[ "${open_ssh}" != *"0.0.0.0/0"* ]]; then
    aws_cli ec2 authorize-security-group-ingress \
      --group-id "${sg_id}" \
      --protocol tcp \
      --port 22 \
      --cidr 0.0.0.0/0 # CIS 5.2 - SSH open to the world
  fi
}

remove_account_password_policy_if_present() {
  if aws iam get-account-password-policy >/dev/null 2>&1; then
    aws iam delete-account-password-policy # CIS 1.5 - remove password policy (weak / absent credentials posture)
  fi
}

print_root_mfa_lab_note() {
  cat <<'EOF'
NOTE (CIS 1.1 - root MFA): This script does not enroll or remove root MFA.
Lab intent: ensure the root user has NO MFA before scanning. Validate in the
AWS Console: Account menu -> Security credentials -> MFA. Removing MFA (if present)
is manual and should only be done in a disposable lab account.
EOF
}

main() {
  require_vars

  local account_id
  account_id="$(aws sts get-caller-identity --query Account --output text)"

  put_public_bucket_misconfiguration
  ensure_iam_user_with_admin_policy
  ensure_single_region_trail "${account_id}"
  ensure_ssh_open_to_world_sg
  print_root_mfa_lab_note
  remove_account_password_policy_if_present

  printf '\n%s\n' "=== Summary (resources ensured for CIS lab misconfiguration state) ==="
  printf '%s\n' "- S3 public exposure bucket: ${BUCKET_NAME} (Block Public Access disabled + public-read bucket policy) [CIS 2.1.1]"
  printf '%s\n' "- IAM user with direct AdministratorAccess: ${IAM_USER_NAME} [CIS 1.16]"
  printf '%s\n' "- Single-region CloudTrail trail: ${TRAIL_NAME} (logs bucket: ${CLOUDTRAIL_LOG_BUCKET}) [CIS 3.1]"
  printf '%s\n' "- Security group name: ${SG_NAME} (SSH TCP/22 from 0.0.0.0/0 in default VPC) [CIS 5.2]"
  printf '%s\n' "- Root MFA: verify manually (expected: MFA not enabled) [CIS 1.1]"
  printf '%s\n' "- Account password policy: deleted if it existed (expected: no policy) [CIS 1.5]"
  printf '%s\n' "- AWS account ID context: ${account_id} (do not publish raw IDs publicly without review)"
}

main "$@"
