#!/usr/bin/env bash
# L2 native REALITY acceptance fixture for Issue #7 first PR.
#
# The script fetches the pinned sing-box release, verifies both the archive
# and the extracted binary against the in-tree pin, and then runs the gated
# native acceptance tests against that exact binary:
#
#   - TestRealityNativeCheck            the compiled v2 candidate is accepted
#                                       by the real pinned kernel
#   - TestRealityIntegrationHandshake... a real VLESS/REALITY handshake
#                                       succeeds, is denied for a wrong UUID
#                                       and is denied for a deleted UUID
#
# The fixture is isolated: it binds loopback only, starts the pinned binary as
# an unprivileged subprocess, and never installs a package, never writes a
# systemd unit and never touches a host service. It is safe to run inside the
# disposable Debian 13 container started by
# .github/workflows/hub-components.yml.
#
# The pin is read from the repository fixture (releases.tsv), which is
# rendered by internal/install/node_ci_test.go from internal/node/release.go.
# The script never hardcodes a second copy of the pin, so the two can not
# drift apart.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

TASK_TEMP=""
PIN_TEMP=""

cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "${PIN_TEMP}" && -d "${PIN_TEMP}" ]]; then
    rm -rf -- "${PIN_TEMP}" || true
  fi
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
  done </etc/os-release

  if [[ "${id}" != "debian" || "${version_id}" != "13" ]]; then
    fail "this CI script requires Debian 13 (found ${id:-unknown} ${version_id:-unknown})"
  fi
}

for tool in curl tar sha256sum awk; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    fail "required command '${tool}' is missing"
  fi
done

require_debian_13

case "$(uname -m)" in
  x86_64) ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  *) fail "unsupported architecture: $(uname -m); supported: x86_64, aarch64" ;;
esac

TEST_BINARY="${REPO_ROOT}/.ci/bin/node.test"
if [[ ! -x "${TEST_BINARY}" ]]; then
  fail "prebuilt test binary not found or not executable: ${TEST_BINARY}; the CI workflow must build it before running this script"
fi

# The pin is rendered by the node package itself, which reads the same
# internal/node/release.go the compiler and the acceptance fixture use.
#
# --- Render the in-tree pin ------------------------------------------------
# The fixture writes releases.tsv from internal/node/release.go, so the script
# consumes the repository's own pin instead of a second hardcoded copy.
PIN_TEMP="$(mktemp -d "${TMPDIR:-/tmp}/meshmux-reality-pin.XXXXXX")" ||
  fail "could not create the pin fixture directory"
MESHMUX_REALITY_PIN_DIR="${PIN_TEMP}" "${TEST_BINARY}" \
  -test.run '^TestWriteRealityReleasePin$' -test.v >"${PIN_TEMP}/fixture.log" 2>&1 ||
  fail "could not render the Node release pin; see ${PIN_TEMP}/fixture.log"

RELEASES_TSV="${PIN_TEMP}/releases.tsv"
if [[ ! -f "${RELEASES_TSV}" ]]; then
  fail "the release pin fixture did not produce releases.tsv"
fi

# The first row is the header; the pin rows are architecture, version,
# source_url, archive_sha256 and binary_sha256.
PIN_ROW="$(awk -F'\t' -v arch="${ARCH}" '$1==arch {print; exit}' "${RELEASES_TSV}")"
if [[ -z "${PIN_ROW}" ]]; then
  fail "the in-tree pin has no ${ARCH} row"
fi

read -r PIN_ARCH PIN_VERSION PIN_URL PIN_ARCHIVE_SHA PIN_BINARY_SHA <<<"${PIN_ROW}"
if [[ "${PIN_ARCH}" != "${ARCH}" ]]; then
  fail "the in-tree pin row does not describe ${ARCH}"
fi
if [[ "${PIN_VERSION}" != "1.14.3" ]]; then
  fail "the in-tree pin version is not the pinned 1.14.3 release"
fi
if [[ "${PIN_URL}" != https://github.com/SagerNet/sing-box/releases/download/v* ]]; then
  fail "the in-tree pin source is not the official SagerNet release"
fi
if [[ "${#PIN_ARCHIVE_SHA}" -ne 64 || "${#PIN_BINARY_SHA}" -ne 64 ]]; then
  fail "the in-tree pin digests are incomplete"
fi
printf 'In-tree pin: sing-box %s (%s)\n' "${PIN_VERSION}" "${ARCH}"

# --- Fetch and verify the pinned release -----------------------------------
TMP_ROOT="${RUNNER_TEMP:-/tmp}"
if [[ ! -d "${TMP_ROOT}" ]]; then
  fail "temporary directory root does not exist: ${TMP_ROOT}"
fi
TASK_TEMP="$(mktemp -d "${TMP_ROOT}/meshmux-reality.XXXXXX")" || fail "could not create a temporary directory"

ARCHIVE="${TASK_TEMP}/sing-box.tar.gz"
printf 'Downloading the pinned sing-box %s archive...\n' "${PIN_VERSION}"
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
  --output "${ARCHIVE}" \
  "${PIN_URL}" || fail "failed to download ${PIN_URL}"

ACTUAL_ARCHIVE_SHA="$(sha256sum -- "${ARCHIVE}" | cut -d' ' -f1)"
if [[ "${ACTUAL_ARCHIVE_SHA}" != "${PIN_ARCHIVE_SHA}" ]]; then
  fail "the downloaded archive SHA-256 does not match the in-tree pin"
fi
printf 'Verified the archive SHA-256 against the in-tree pin.\n'

EXTRACT_DIR="${TASK_TEMP}/sing-box"
mkdir -- "${EXTRACT_DIR}"
tar \
  --extract \
  --gzip \
  --file="${ARCHIVE}" \
  --directory="${EXTRACT_DIR}" \
  --no-same-owner \
  --no-same-permissions || fail "failed to extract the sing-box archive"

# The official archive always unpacks to a directory named after the release
# and the architecture. The path is derived from the pinned version, so the
# script never picks up an unexpected file out of the archive.
SINGBOX_BIN="${EXTRACT_DIR}/sing-box-${PIN_VERSION}-linux-${ARCH}/sing-box"
if [[ ! -f "${SINGBOX_BIN}" ]]; then
  fail "the pinned sing-box binary was not found at the expected archive path"
fi
chmod 0755 -- "${SINGBOX_BIN}"

ACTUAL_BINARY_SHA="$(sha256sum -- "${SINGBOX_BIN}" | cut -d' ' -f1)"
if [[ "${ACTUAL_BINARY_SHA}" != "${PIN_BINARY_SHA}" ]]; then
  fail "the extracted binary SHA-256 does not match the in-tree pin"
fi
printf 'Verified the binary SHA-256 against the in-tree pin.\n'

REPORTED_VERSION="$("${SINGBOX_BIN}" version | head -1 | awk '{print $3}')"
if [[ "${REPORTED_VERSION}" != "${PIN_VERSION}" ]]; then
  fail "the pinned binary reports version ${REPORTED_VERSION}, expected ${PIN_VERSION}"
fi

# --- Run the gated native acceptance tests ---------------------------------
# Both tests compare the binary digest against the same in-tree pin, so the
# environment cannot redirect the fixture to another build.
export MESHMUX_REALITY_CHECK_BINARY="${SINGBOX_BIN}"
export MESHMUX_REALITY_INTEGRATION_BINARY="${SINGBOX_BIN}"

TEST_LOG="${TASK_TEMP}/reality-native.log"
cd -- "${REPO_ROOT}"

set +e
"${TEST_BINARY}" \
  -test.run '^TestRealityNativeCheck$|^TestRealityIntegrationHandshake' \
  -test.v \
  -test.timeout=5m 2>&1 | tee "${TEST_LOG}"
test_status="${PIPESTATUS[0]}"
set -e

if (( test_status != 0 )); then
  fail "the native REALITY acceptance tests failed (exit status ${test_status})"
fi

# A SKIP is not a pass: the binary was available, so the fixture had to run.
for required in TestRealityNativeCheck TestRealityIntegrationHandshakeAcceptsAndDeniesCredentials; do
  if ! grep -Eq -- "--- PASS: ${required}( |$)" "${TEST_LOG}"; then
    fail "${required} did not report PASS"
  fi
  if grep -Eq -- "--- SKIP: ${required}( |$)" "${TEST_LOG}"; then
    fail "${required} was skipped; SKIP is not accepted"
  fi
done

if ! grep -Fxq 'PASS' "${TEST_LOG}"; then
  fail "the test binary did not report an overall PASS"
fi

# --- The Line candidate and the publish gate on the same pinned kernel ------
# The rendered Line document is what the node runs and what the Hub gates, so
# the same verified binary checks both: the candidate renderer with and without
# an Out, and the publish gate over a stored Out-selecting candidate. Both tests
# skip without MESHMUX_SINGBOX_TEST_BINARY, so the variable is set here and a
# SKIP is treated as a failure.
export MESHMUX_SINGBOX_TEST_BINARY="${SINGBOX_BIN}"
WEB_TEST="${REPO_ROOT}/.ci/bin/web-handler.test"
if [[ ! -x "${WEB_TEST}" ]]; then
  fail "prebuilt test binary not found or not executable: ${WEB_TEST}; the CI workflow must build it before running this script"
fi

run_route_gate() {
  local suite_name="$1"
  local suite_binary="$2"
  local suite_pattern="$3"
  local suite_log="${TASK_TEMP}/${suite_name}-route-gate.log"
  local suite_status=0

  set +e
  "${suite_binary}" \
    -test.run "${suite_pattern}" \
    -test.v \
    -test.timeout=5m 2>&1 | tee "${suite_log}"
  suite_status="${PIPESTATUS[0]}"
  set -e
  if (( suite_status != 0 )); then
    fail "the ${suite_name} route gate failed against the pinned kernel (exit status ${suite_status})"
  fi
  if ! grep -Eq -- '--- PASS: ' "${suite_log}"; then
    fail "the ${suite_name} route gate reported no PASS"
  fi
  if grep -Eq -- '--- SKIP: ' "${suite_log}"; then
    fail "the ${suite_name} route gate was skipped; SKIP is not accepted"
  fi
}

run_route_gate node "${TEST_BINARY}" '^TestCompileCandidateRouteNativeCheck$'
run_route_gate web "${WEB_TEST}" '^TestPublishGateRealKernelOutCandidate$'

printf 'PASS: the pinned sing-box %s accepted the compiled candidate, the Out-selecting Line candidate and the publish gate, and served a real isolated VLESS/REALITY handshake.\n' "${PIN_VERSION}"
