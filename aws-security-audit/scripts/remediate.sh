#!/usr/bin/env bash
#
# WARNING - FOR AUDIT LAB USE ONLY.
# Reverses the intentional misconfigurations created by introduce-misconfigs.sh.
#
# Run this script AFTER Prowler "before" screenshots and evidence exports are
# captured for the audit report. Remediation changes the live account state and
# will alter subsequent scan results.
#
set -euo pipefail

# --- Lab configuration (must match introduce-misconfigs.sh) ---
BUCKET_NAME="${BUCKET_NAME:-}"
REGION="${REGION:-}"
SG_NAME="${SG_NAME:-}"
IAM_USER_NAME="${IAM_USER_NAME:-cis-lab-admin-user}"
TRAIL_NAME="${TRAIL_NAME:-cis-lab-single-region-trail}"
CLOUDTRAIL_LOG_BUCKET="${CLOUDTRAIL_LOG_BUCKET:-}"

require_vars() {
  if [[ -z "${BUCKET_NAME}" ]]; then
    printf '%s\n' "ERROR: Set BUCKET_NAME to the public lab bucket name." >&2
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

empty_bucket_if_exists() {
  local name="$1"
  if ! bucket_exists "${name}"; then
    return 0
  fi
  aws_cli s3 rm "s3://${name}/" --recursive # Lab cleanup - remove objects before bucket deletion
}

delete_bucket_if_exists() {
  local name="$1"
  if ! bucket_exists "${name}"; then
    return 0
  fi
  aws_cli s3api delete-bucket --bucket "${name}" # Lab cleanup - remove bucket after emptying
}

remediate_public_s3_bucket() {
  if ! bucket_exists "${BUCKET_NAME}"; then
    return 0
  fi

  # Remove public bucket policy first (if present), then re-enable Block Public Access
  aws_cli s3api delete-bucket-policy --bucket "${BUCKET_NAME}" 2>/dev/null || true # CIS 2.1.1 - remove anonymous access policy

  aws_cli s3api put-public-access-block \
    --bucket "${BUCKET_NAME}" \
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" # CIS 2.1.1 - restore Block Public Access

  empty_bucket_if_exists "${BUCKET_NAME}"
  delete_bucket_if_exists "${BUCKET_NAME}"
}

remediate_iam_user_admin_attachment() {
  if ! aws iam get-user --user-name "${IAM_USER_NAME}" >/dev/null 2>&1; then
    return 0
  fi

  aws iam detach-user-policy \
    --user-name "${IAM_USER_NAME}" \
    --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess" 2>/dev/null || true # CIS 1.16 - remove direct AdministratorAccess attachment

  local policy_name
  while IFS= read -r policy_name; do
    [[ -z "${policy_name}" ]] && continue
    aws iam delete-user-policy --user-name "${IAM_USER_NAME}" --policy-name "${policy_name}" || true
  done < <(aws iam list-user-policies --user-name "${IAM_USER_NAME}" --query 'PolicyNames[]' --output text 2>/dev/null | tr '\t' '\n')

  # Remove access keys (lab cleanup; idempotent per key)
  local kid
  while IFS= read -r kid; do
    [[ -z "${kid}" ]] && continue
    aws iam delete-access-key --user-name "${IAM_USER_NAME}" --access-key-id "${kid}" || true
  done < <(aws iam list-access-keys --user-name "${IAM_USER_NAME}" --query 'AccessKeyMetadata[].AccessKeyId' --output text | tr '\t' '\n')

  # Remove login profile if present (console password)
  aws iam delete-login-profile --user-name "${IAM_USER_NAME}" 2>/dev/null || true

  aws iam delete-user --user-name "${IAM_USER_NAME}" # CIS 1.16 - delete lab IAM user after detaching policies
}

remediate_cloudtrail_trail() {
  local trail_count
  trail_count="$(aws_cli cloudtrail describe-trails --trail-name-list "${TRAIL_NAME}" --query 'length(trailList)' --output text)"

  if [[ "${trail_count}" != "0" ]]; then
    aws_cli cloudtrail stop-logging --name "${TRAIL_NAME}" 2>/dev/null || true # CIS 3.1 - stop logging before trail deletion (lab cleanup)
    aws_cli cloudtrail delete-trail --name "${TRAIL_NAME}" # CIS 3.1 - remove intentionally misconfigured single-region trail
  fi

  empty_bucket_if_exists "${CLOUDTRAIL_LOG_BUCKET}"
  if bucket_exists "${CLOUDTRAIL_LOG_BUCKET}"; then
    aws_cli s3api delete-bucket-policy --bucket "${CLOUDTRAIL_LOG_BUCKET}" 2>/dev/null || true
  fi
  delete_bucket_if_exists "${CLOUDTRAIL_LOG_BUCKET}"
}

remediate_security_group_ssh() {
  local vpc_id
  vpc_id="$(aws_cli ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
  if [[ -z "${vpc_id}" || "${vpc_id}" == "None" ]]; then
    return 0
  fi

  local sg_id
  sg_id="$(aws_cli ec2 describe-security-groups --filters "Name=group-name,Values=${SG_NAME}" "Name=vpc-id,Values=${vpc_id}" --query 'SecurityGroups[0].GroupId' --output text)"
  if [[ -z "${sg_id}" || "${sg_id}" == "None" ]]; then
    return 0
  fi

  local open_ssh
  # shellcheck disable=SC2016
  open_ssh="$(aws_cli ec2 describe-security-groups --group-ids "${sg_id}" --query 'SecurityGroups[0].IpPermissions[?FromPort==`22` && ToPort==`22` && IpProtocol==`tcp`].IpRanges[?CidrIp==`0.0.0.0/0`].CidrIp' --output text)"
  if [[ "${open_ssh}" == *"0.0.0.0/0"* ]]; then
    aws_cli ec2 revoke-security-group-ingress \
      --group-id "${sg_id}" \
      --protocol tcp \
      --port 22 \
      --cidr 0.0.0.0/0 # CIS 5.2 - remove world-open SSH ingress
  fi

  aws_cli ec2 delete-security-group --group-id "${sg_id}" 2>/dev/null || true # CIS 5.2 - delete lab SG if not in use
}

restore_account_password_policy() {
  # CIS 1.5 - restore a CIS-minimum style password policy (minimum length 14)
  aws iam update-account-password-policy \
    --minimum-password-length 14 \
    --require-symbols \
    --require-numbers \
    --require-uppercase-characters \
    --require-lowercase-characters \
    --max-password-age 90 \
    --password-reuse-prevention 24 # CIS 1.5 - enforce minimum length and complexity baseline
}

print_root_mfa_remediation_note() {
  cat <<'EOF'
NOTE (CIS 1.1 - root MFA): Enabling MFA for the root user is performed in the
AWS Console (Account -> Security credentials -> MFA). This script does not
modify root MFA devices. Complete that step manually, then re-run Prowler to
verify the control passes.
EOF
}

main() {
  require_vars

  remediate_cloudtrail_trail
  remediate_public_s3_bucket
  remediate_iam_user_admin_attachment
  remediate_security_group_ssh
  restore_account_password_policy
  print_root_mfa_remediation_note

  printf '\n%s\n' "=== Summary (lab misconfigurations reversed or queued for manual steps) ==="
  printf '%s\n' "- CloudTrail trail removed (if present): ${TRAIL_NAME}; logs bucket deleted if empty: ${CLOUDTRAIL_LOG_BUCKET} [CIS 3.1]"
  printf '%s\n' "- Public S3 bucket removed (if present): ${BUCKET_NAME} [CIS 2.1.1]"
  printf '%s\n' "- IAM lab user removed (if present): ${IAM_USER_NAME} [CIS 1.16]"
  printf '%s\n' "- Security group cleaned up (if present): ${SG_NAME} [CIS 5.2]"
  printf '%s\n' "- Account password policy restored (minimum length 14 + complexity) [CIS 1.5]"
  printf '%s\n' "- Root MFA: enable manually in Console, then verify with Prowler [CIS 1.1]"
}

main "$@"
