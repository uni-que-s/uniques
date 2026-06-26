#!/bin/sh
# Entrypoint for the QuantumVault GitHub Action.
# Args: <scan-path> <fail-on> <sarif-file>
set -e

SCAN_PATH="${1:-.}"
FAIL_ON="$2"
SARIF_FILE="${3:-quantumvault.sarif}"
BASELINE="$4"

# GitHub mounts the repository at /github/workspace and sets it as the workdir.
cd "${GITHUB_WORKSPACE:-/github/workspace}"

echo "QuantumVault: scanning '${SCAN_PATH}' -> ${SARIF_FILE}"
# SARIF carries the full inventory for code-scanning; the build gate (below) is
# what ratchets on new findings.
node /app/dist/cli.js "${SCAN_PATH}" --sarif > "${SARIF_FILE}"
node /app/dist/cli.js "${SCAN_PATH}"

if [ -n "${FAIL_ON}" ]; then
  if [ -n "${BASELINE}" ]; then
    echo "QuantumVault: gating on NEW findings >= ${FAIL_ON} (baseline: ${BASELINE})"
    node /app/dist/cli.js "${SCAN_PATH}" --baseline "${BASELINE}" --fail-on "${FAIL_ON}"
  else
    echo "QuantumVault: gating on severity >= ${FAIL_ON}"
    node /app/dist/cli.js "${SCAN_PATH}" --fail-on "${FAIL_ON}"
  fi
fi
