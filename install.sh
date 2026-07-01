#!/usr/bin/env bash
#
# UniQueS — one-command on-prem install.
#
#   ./install.sh                        # start with the free 30-day trial
#   ./install.sh --license UQS2.xxx     # start fully licensed
#   ./install.sh --license-file key.txt # read the key from a file (post-quantum keys are large)
#   QV_LICENSE=UQS2.xxx ./install.sh    # same, via environment
#
# Brings up the self-hosted stack (server + dashboard) with Docker Compose, waits
# for it to come healthy, applies a license key if given, and prints where to go.
# Everything runs inside your network — no data leaves the host.
set -euo pipefail

DASH_PORT="${QV_WEB_PORT:-8080}"
API_PORT="${QV_API_PORT:-4000}"
LICENSE="${QV_LICENSE:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    --license) LICENSE="${2:-}"; shift 2 ;;
    --license=*) LICENSE="${1#*=}"; shift ;;
    --license-file) LICENSE="$(tr -d '[:space:]' < "${2:?--license-file needs a path}")"; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

cd "$(dirname "$0")"

# --- preflight -------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  echo "✗ Docker is required but not found. Install Docker Desktop / Engine first: https://docs.docker.com/get-docker/" >&2
  exit 1
fi
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "✗ Docker Compose is required (Docker Desktop bundles it, or install the compose plugin)." >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "✗ The Docker daemon isn't running. Start Docker and re-run ./install.sh." >&2
  exit 1
fi

# --- bring up the stack ----------------------------------------------------
echo "→ Building and starting UniQueS (this can take a minute on first run)…"
QV_LICENSE="$LICENSE" "${COMPOSE[@]}" up -d --build

# --- wait for health -------------------------------------------------------
printf "→ Waiting for the API to come healthy"
HEALTH_URL="http://localhost:${API_PORT}/api/health"
for _ in $(seq 1 60); do
  if curl -fsS "$HEALTH_URL" >/dev/null 2>&1; then ok=1; break; fi
  printf "."; sleep 2
done
echo
if [ "${ok:-0}" != "1" ]; then
  echo "✗ The API did not become healthy in time. Check logs with: ${COMPOSE[*]} logs server" >&2
  exit 1
fi

VERSION="$(curl -fsS "$HEALTH_URL" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
LIC_MSG="$(curl -fsS "http://localhost:${API_PORT}/api/license" | sed -n 's/.*"message":"\([^"]*\)".*/\1/p')"

cat <<EOF

✓ UniQueS is running (v${VERSION:-?}).

  Dashboard : http://localhost:${DASH_PORT}
  API       : http://localhost:${API_PORT}
  License   : ${LIC_MSG:-trial active}

Next:
  • Open the dashboard and scan a repository — your source never leaves this host.
  • No key yet? You're on the 30-day trial. Activate later in the dashboard,
    or re-run:  ./install.sh --license-file your-key.txt
  • Stop / start:  ${COMPOSE[*]} down   |   ${COMPOSE[*]} up -d
EOF
