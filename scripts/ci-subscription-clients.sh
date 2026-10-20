#!/usr/bin/env bash
# CI-only subscription client import test.
# The workflow provisions the Debian 13 container and its apt dependencies.
# This script does not install packages or modify the host.

set -Eeuo pipefail

SINGBOX_VERSION="1.14.3"
MIHOMO_VERSION="1.19.32"

SINGBOX_SHA256_AMD64="e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee"
SINGBOX_SHA256_ARM64="29dae24d76bea3bc62d07dd3e60cfc12003de7debbd6b768df9be9c68360174e"
MIHOMO_SHA256_AMD64_COMPATIBLE="ba3ce607747a07f948fc35780e108a4a7c7f552a38b9bd4d115f313ebcb89c20"
MIHOMO_SHA256_ARM64="9dd862e28b46ff7d775f169cceebc28deccaa0a9e804237d421cd2571e0caba0"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

TASK_TEMP=""

cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "${TASK_TEMP}" && -d "${TASK_TEMP}" ]]; then
    rm -rf -- "${TASK_TEMP}" || true
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_debian_13() {
  local id=""
  local version_id=""

  if [[ ! -r /etc/os-release ]]; then
    fail "cannot read /etc/os-release; this CI script requires Debian 13"
  fi

  while IFS='=' read -r key value; do
    value="${value%$'\r'}"
    value="${value#\"}"
    value="${value%\"}"
    case "${key}" in
      ID) id="${value}" ;;
      VERSION_ID) version_id="${value}" ;;
    esac
  done < /etc/os-release

  if [[ "${id}" != "debian" || "${version_id}" != "13" ]]; then
    fail "this CI script requires Debian 13 (found ${id:-unknown} ${version_id:-unknown})"
  fi
}

curl_fail_retry3() {
  local url="$1"
  local destination="$2"

  curl \
    --fail \
    --silent \
    --show-error \
    --location \
    --retry 3 \
    --retry-delay 2 \
    --retry-connrefused \
    --connect-timeout 30 \
    --max-time 300 \
    --proto '=https' \
    --tlsv1.2 \
    --output "${destination}" \
    "${url}"
}

verify_sha256() {
  local file="$1"
  local expected="$2"
  local actual=""

  if [[ ! -f "${file}" ]]; then
    fail "cannot verify missing file: ${file}"
  fi
  if ! actual="$(sha256sum -- "${file}")"; then
    fail "could not calculate SHA-256 for ${file}"
  fi
  actual="${actual%% *}"
  if [[ "${actual}" != "${expected}" ]]; then
    fail "SHA-256 mismatch for ${file##*/}: expected ${expected}, got ${actual}"
  fi
}

require_debian_13

for tool in curl tar gzip sha256sum; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    fail "required command '${tool}' is missing; provision curl, tar, gzip and coreutils (sha256sum) in the Debian 13 CI container via the workflow"
  fi
done

case "$(uname -m)" in
  x86_64)
    ARCH="amd64"
    MIHOMO_ARCH="amd64-compatible"
    SINGBOX_SHA256="${SINGBOX_SHA256_AMD64}"
    MIHOMO_SHA256="${MIHOMO_SHA256_AMD64_COMPATIBLE}"
    ;;
  aarch64)
    ARCH="arm64"
    MIHOMO_ARCH="arm64"
    SINGBOX_SHA256="${SINGBOX_SHA256_ARM64}"
    MIHOMO_SHA256="${MIHOMO_SHA256_ARM64}"
    ;;
  *)
    fail "unsupported architecture: $(uname -m); supported: x86_64, aarch64"
    ;;
esac

TEST_BINARY="${REPO_ROOT}/.ci/bin/subscription.test"
if [[ ! -x "${TEST_BINARY}" ]]; then
  fail "prebuilt test binary not found or not executable: ${TEST_BINARY}; the CI workflow must build it before running this script"
fi

TMP_ROOT="${RUNNER_TEMP:-/tmp/opencode}"
if [[ ! -d "${TMP_ROOT}" ]]; then
  fail "temporary directory root does not exist: ${TMP_ROOT}"
fi
TASK_TEMP="$(mktemp -d "${TMP_ROOT}/meshmux-subscription-clients.XXXXXX")" || fail "could not create a temporary directory under ${TMP_ROOT}"

SINGBOX_ARCHIVE="${TASK_TEMP}/sing-box-${SINGBOX_VERSION}-linux-${ARCH}.tar.gz"
SINGBOX_URL="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${ARCH}.tar.gz"

MIHOMO_ARCHIVE="${TASK_TEMP}/mihomo-linux-${MIHOMO_ARCH}-v${MIHOMO_VERSION}.gz"
MIHOMO_URL="https://github.com/MetaCubeX/mihomo/releases/download/v${MIHOMO_VERSION}/mihomo-linux-${MIHOMO_ARCH}-v${MIHOMO_VERSION}.gz"

printf 'Downloading sing-box %s (%s)...\n' "${SINGBOX_VERSION}" "${ARCH}"
curl_fail_retry3 "${SINGBOX_URL}" "${SINGBOX_ARCHIVE}" || fail "failed to download ${SINGBOX_URL}"
verify_sha256 "${SINGBOX_ARCHIVE}" "${SINGBOX_SHA256}"
printf 'Verified SHA-256 for sing-box %s.\n' "${SINGBOX_VERSION}"

SINGBOX_EXTRACT_DIR="${TASK_TEMP}/sing-box"
mkdir -- "${SINGBOX_EXTRACT_DIR}"
tar \
  --extract \
  --gzip \
  --file="${SINGBOX_ARCHIVE}" \
  --directory="${SINGBOX_EXTRACT_DIR}" \
  --no-same-owner \
  --no-same-permissions || fail "failed to extract sing-box archive"

SINGBOX_BIN="${SINGBOX_EXTRACT_DIR}/sing-box-${SINGBOX_VERSION}-linux-${ARCH}/sing-box"
if [[ ! -f "${SINGBOX_BIN}" ]]; then
  fail "sing-box binary not found after extraction: ${SINGBOX_BIN}"
fi
chmod 0755 -- "${SINGBOX_BIN}"

printf 'Downloading mihomo %s (%s)...\n' "${MIHOMO_VERSION}" "${MIHOMO_ARCH}"
curl_fail_retry3 "${MIHOMO_URL}" "${MIHOMO_ARCHIVE}" || fail "failed to download ${MIHOMO_URL}"
verify_sha256 "${MIHOMO_ARCHIVE}" "${MIHOMO_SHA256}"
printf 'Verified SHA-256 for mihomo %s.\n' "${MIHOMO_VERSION}"

MIHOMO_BIN="${TASK_TEMP}/mihomo"
gzip --decompress --stdout -- "${MIHOMO_ARCHIVE}" >"${MIHOMO_BIN}" || fail "failed to extract mihomo binary"
if [[ ! -s "${MIHOMO_BIN}" ]]; then
  fail "mihomo binary is empty after extraction"
fi
chmod 0755 -- "${MIHOMO_BIN}"

export MESHMUX_SINGBOX_TEST_BINARY="${SINGBOX_BIN}"
export MESHMUX_MIHOMO_TEST_BINARY="${MIHOMO_BIN}"

TEST_LOG="${TASK_TEMP}/subscription-client-import.log"
cd -- "${REPO_ROOT}"

set +e
"${TEST_BINARY}" \
  -test.run '^TestSubscriptionClientImport$|^TestSubscriptionExportHandshakeDataPath$' \
  -test.v \
  -test.timeout=2m 2>&1 | tee "${TEST_LOG}"
test_status="${PIPESTATUS[0]}"
set -e

if (( test_status != 0 )); then
  fail "TestSubscriptionClientImport failed (exit status ${test_status})"
fi

passed=0
handshake_passed=0
suite_passed=0
while IFS= read -r line; do
  case "${line}" in
    "--- SKIP:"*)
      fail "TestSubscriptionClientImport was skipped; SKIP is not accepted"
      ;;
    "--- PASS: TestSubscriptionClientImport"|"--- PASS: TestSubscriptionClientImport "*)
      passed=1
      ;;
    "--- PASS: TestSubscriptionExportHandshakeDataPath"|"--- PASS: TestSubscriptionExportHandshakeDataPath "*)
      handshake_passed=1
      ;;
    "PASS")
      suite_passed=1
      ;;
  esac
done <"${TEST_LOG}"

if (( passed != 1 )); then
  fail "TestSubscriptionClientImport did not report PASS"
fi
if (( handshake_passed != 1 )); then
  fail "TestSubscriptionExportHandshakeDataPath did not report PASS"
fi
if (( suite_passed != 1 )); then
  fail "test binary did not report overall PASS"
fi

printf 'PASS: generated subscriptions imported and carried traffic through both Lines\n'
