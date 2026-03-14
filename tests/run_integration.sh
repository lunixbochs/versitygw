#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/.." && pwd)

ROOT_ACCESS_KEY=${ROOT_ACCESS_KEY:-user}
ROOT_SECRET_KEY=${ROOT_SECRET_KEY:-pass}
AWS_REGION=${AWS_REGION:-us-east-1}
VGW_HOST=${VGW_HOST:-127.0.0.1}
VGW_PORT=7171
VGW_HEALTH_PATH=${VGW_HEALTH_PATH:-/health}
KEEP_TMPDIR=${KEEP_TMPDIR:-0}
VGW_BUILD=${VGW_BUILD:-1}

usage() {
  cat <<'EOF'
Usage: ./tests/run_integration.sh [options] [test_or_group ...]

Options:
  -p, --port PORT   Gateway listen port (default: 7171)
  -h, --help        Show this help

If no tests or groups are provided, the script runs:
  full-flow --versioning-enabled --parallel
  posix --versioning-enabled
EOF
}

TESTS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    -p|--port)
      if [ "$#" -lt 2 ]; then
        printf 'missing value for %s\n' "$1" >&2
        usage >&2
        exit 1
      fi
      VGW_PORT=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      while [ "$#" -gt 0 ]; do
        TESTS+=("$1")
        shift
      done
      ;;
    -*)
      printf 'unknown option: %s\n' "$1" >&2
      usage >&2
      exit 1
      ;;
    *)
      TESTS+=("$1")
      shift
      ;;
  esac
done

if [ "${#TESTS[@]}" -eq 0 ]; then
  TESTS=("full-flow" "posix")
  USE_DEFAULT_FLAGS=1
else
  USE_DEFAULT_FLAGS=0
fi

TMPDIR_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/vgw-exa.XXXXXX")
VGW_BIN=${VGW_BIN:-"${TMPDIR_ROOT}/versitygw"}
GW_ROOT="${TMPDIR_ROOT}/gwroot"
IAM_DIR="${TMPDIR_ROOT}/iam"
VERSIONING_DIR="${TMPDIR_ROOT}/versioning"
SIDECAR_DIR="${TMPDIR_ROOT}/meta"
VGW_LOG="${TMPDIR_ROOT}/versitygw.log"
GW_PID=""

if ! command -v curl >/dev/null 2>&1; then
  printf 'curl is required\n' >&2
  exit 1
fi

cleanup() {
  local status=$?

  if [ -n "${GW_PID}" ] && kill -0 "${GW_PID}" 2>/dev/null; then
    kill "${GW_PID}" 2>/dev/null || true
    wait "${GW_PID}" 2>/dev/null || true
  fi

  if [ "${status}" -eq 0 ] && [ "${KEEP_TMPDIR}" != "1" ]; then
    rm -rf "${TMPDIR_ROOT}"
  else
    printf 'retained temp dir: %s\n' "${TMPDIR_ROOT}" >&2
    printf 'gateway log: %s\n' "${VGW_LOG}" >&2
  fi

  exit "${status}"
}

trap cleanup EXIT INT TERM

mkdir -p "${GW_ROOT}" "${IAM_DIR}" "${VERSIONING_DIR}" "${SIDECAR_DIR}"

VGW_ENDPOINT=${VGW_ENDPOINT:-http://${VGW_HOST}:${VGW_PORT}}

export GOCACHE=${GOCACHE:-"${TMPDIR_ROOT}/gocache"}

if [ "${VGW_BUILD}" = "1" ]; then
  printf 'building versitygw: go build -o %q ./cmd/versitygw\n' "${VGW_BIN}"
  (
    cd "${REPO_ROOT}"
    go build -o "${VGW_BIN}" ./cmd/versitygw
  )
fi

VGW_CMD=(
  "${VGW_BIN}"
  --access "${ROOT_ACCESS_KEY}"
  --secret "${ROOT_SECRET_KEY}"
  --region "${AWS_REGION}"
  --port "${VGW_HOST}:${VGW_PORT}"
  --health "${VGW_HEALTH_PATH}"
  --iam-dir "${IAM_DIR}"
  posix
  --versioning-dir "${VERSIONING_DIR}"
  --sidecar "${SIDECAR_DIR}"
  "${GW_ROOT}"
)

printf 'starting versitygw command:\n'
printf '  %q' "${VGW_CMD[@]}"
printf '\n'
"${VGW_CMD[@]}" >"${VGW_LOG}" 2>&1 &
GW_PID=$!

HEALTH_URL="${VGW_ENDPOINT}${VGW_HEALTH_PATH}"
for _ in $(seq 1 60); do
  if curl -fsS "${HEALTH_URL}" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "${GW_PID}" 2>/dev/null; then
    cat "${VGW_LOG}" >&2
    exit 1
  fi
  sleep 1
done

if ! curl -fsS "${HEALTH_URL}" >/dev/null 2>&1; then
  printf 'gateway did not become ready: %s\n' "${HEALTH_URL}" >&2
  cat "${VGW_LOG}" >&2
  exit 1
fi

for test_name in "${TESTS[@]}"; do
  TEST_CMD=(
    "${VGW_BIN}"
    --region "${AWS_REGION}"
    test
    --access "${ROOT_ACCESS_KEY}"
    --secret "${ROOT_SECRET_KEY}"
    --endpoint "${VGW_ENDPOINT}"
    "${test_name}"
  )
  if [ "${USE_DEFAULT_FLAGS}" = "1" ]; then
    case "${test_name}" in
      full-flow)
        TEST_CMD+=(--versioning-enabled --parallel)
        ;;
      posix)
        TEST_CMD+=(--versioning-enabled)
        ;;
    esac
  fi

  printf 'running integration test:\n'
  printf '  %q' "${TEST_CMD[@]}"
  printf '\n'
  (
    cd "${REPO_ROOT}"
    "${TEST_CMD[@]}"
  )
done
