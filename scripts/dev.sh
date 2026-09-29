#!/usr/bin/env bash
#
# Run the whole thing on this machine: the portal from the working tree, and a
# model for the assistant to talk to.
#
#   scripts/dev.sh              # start everything, reload on save
#   scripts/dev.sh status       # what is running, and where
#   scripts/dev.sh stop         # stop what this script started
#   scripts/dev.sh logs         # follow the portal's log
#
#   --model qwen2.5:7b          # a better model (see the note below)
#   --port 8471                 # portal port
#   --data data/customer-a      # a separate database, for a second instance
#   --upgrade-url URL           # where its Renew button points
#   --cluster CONTEXT           # borrow a cluster's Ollama over a port-forward
#   --no-ai                     # skip the model entirely
#
# WHERE THE MODEL COMES FROM, in order of preference:
#   1. a native `ollama` on this machine — on Apple Silicon this uses the GPU
#      through Metal, which is several times faster than anything in a container
#   2. a Docker container — works with no installation, but CPU-only, because a
#      Linux container on macOS cannot reach the Mac's GPU
#   3. --cluster: a port-forward to an Ollama already running in a cluster
#
# WHAT IT NEVER DOES
#   It only ever stops processes it started itself, recorded by pid in
#   data/dev/. No pattern-matching kills: a stray `pkill -f portal` once took
#   out a portal somebody was using.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=8471
DATA=""
UPGRADE_URL=""
MODEL="llama3.2:3b"
CLUSTER=""
WANT_AI=1
CMD="up"
OLLAMA_PORT=11434
RUN="data/dev"
CONTAINER="portal-dev-ollama"

while [[ $# -gt 0 ]]; do
  case "$1" in
    up|stop|status|logs) CMD="$1"; shift ;;
    --model) MODEL="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --data) DATA="$2"; shift 2 ;;
    --upgrade-url) UPGRADE_URL="$2"; shift 2 ;;
    --cluster) CLUSTER="$2"; shift 2 ;;
    --no-ai) WANT_AI=0; shift ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "$RUN"
say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m  !\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m  ✓\033[0m %s\n' "$*"; }

PORTAL_PID="portal-$PORT"

alive() {                        # alive <pidfile>
  local f="$RUN/$1.pid"
  [[ -f "$f" ]] && kill -0 "$(cat "$f")" 2>/dev/null
}
stop_pid() {                     # stop_pid <pidfile> <label>
  local f="$RUN/$1.pid"
  if alive "$1"; then
    kill "$(cat "$f")" 2>/dev/null || true
    sleep 1
    kill -0 "$(cat "$f")" 2>/dev/null && kill -9 "$(cat "$f")" 2>/dev/null || true
    ok "stopped $2"
  fi
  rm -f "$f"
}
listening() { lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }

# ── the model ──────────────────────────────────────────────────
start_model() {
  [[ "$WANT_AI" == 1 ]] || { warn "assistant disabled (--no-ai)"; return; }

  if [[ -n "$CLUSTER" ]]; then
    say "borrowing the model in $CLUSTER"
    kubectl --context "$CLUSTER" -n portal port-forward \
      svc/portal-config-portal-ollama "$OLLAMA_PORT:11434" \
      > "$RUN/portforward.log" 2>&1 &
    echo $! > "$RUN/portforward.pid"
    sleep 3
    if curl -sf "http://127.0.0.1:$OLLAMA_PORT/api/tags" >/dev/null; then
      ok "port-forward to the cluster's Ollama is up"
    else
      warn "the port-forward did not answer — see $RUN/portforward.log"
    fi
    return
  fi

  if listening "$OLLAMA_PORT"; then
    ok "something already serves $OLLAMA_PORT — reusing it"
  elif command -v ollama > /dev/null; then
    say "starting the native Ollama (GPU-accelerated on Apple Silicon)"
    # flash attention and a quantised KV cache: both cut prompt-processing time,
    # which is most of the wait when the briefing is a couple of thousand tokens
    OLLAMA_FLASH_ATTENTION=1 OLLAMA_KV_CACHE_TYPE=q8_0 \
      ollama serve > "$RUN/ollama.log" 2>&1 &
    echo $! > "$RUN/ollama.pid"
    for _ in $(seq 30); do
      curl -sf "http://127.0.0.1:$OLLAMA_PORT/api/tags" >/dev/null && break
      sleep 1
    done
    ok "native Ollama is up"
  elif docker info > /dev/null 2>&1; then
    say "no native Ollama — using Docker (CPU only; see the header for why)"
    docker volume create "$CONTAINER-models" >/dev/null
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    docker run -d --name "$CONTAINER" \
      -p "$OLLAMA_PORT:11434" \
      -v "$CONTAINER-models:/root/.ollama" \
      -e OLLAMA_KEEP_ALIVE=30m \
      ollama/ollama:0.12.6 > /dev/null
    for _ in $(seq 60); do
      curl -sf "http://127.0.0.1:$OLLAMA_PORT/api/tags" >/dev/null && break
      sleep 1
    done
    ok "Ollama container is up (models cached in the $CONTAINER-models volume)"
  else
    warn "no Ollama and no Docker — the assistant will be unconfigured."
    warn "install one, or point at a cluster: scripts/dev.sh --cluster CONTEXT"
    WANT_AI=0
    return
  fi

  # ── the model itself ──
  # Verified, not assumed. The first version of this hid the pull's stderr and
  # announced success either way; the model was never downloaded and only the
  # assistant's first question found out. So: run it visibly, then ask the API
  # what it actually has.
  have_model() {
    curl -sf "http://127.0.0.1:$OLLAMA_PORT/api/tags" 2>/dev/null \
      | grep -q "\"$MODEL\""
  }
  if have_model; then
    ok "$MODEL is already downloaded"
  else
    say "pulling $MODEL — about 2 GB, once (progress below)"
    if [[ -n "$CLUSTER" ]]; then
      warn "not pulling into someone else's cluster; it will fetch on first use"
    elif command -v ollama > /dev/null; then
      OLLAMA_HOST="http://127.0.0.1:$OLLAMA_PORT" ollama pull "$MODEL" || true
    else
      docker exec "$CONTAINER" ollama pull "$MODEL" || true
    fi
    if have_model; then
      ok "$MODEL downloaded"
    else
      warn "the pull did not leave $MODEL on the server."
      warn "the assistant still works — the model downloads on the first"
      warn "question instead, so that one answer will be slow."
    fi
  fi
}

# ── the portal ─────────────────────────────────────────────────
start_portal() {
  if listening "$PORT"; then
    if alive "$PORTAL_PID"; then
      ok "the portal this script started is already on $PORT"
      return
    fi
    warn "port $PORT is taken by a process this script did not start."
    warn "leaving it alone — stop it yourself, or use --port to pick another."
    return
  fi
  [[ -x .venv/bin/uvicorn ]] || {
    say "creating the virtualenv"
    python3 -m venv .venv
    ./.venv/bin/pip install -qr requirements.txt
  }
  say "starting the portal on http://127.0.0.1:$PORT (reloads on save)"
  local ai_env=()
  # A separate database makes this a genuinely separate installation: its own
  # projects and its own users. Without it a second instance would share the
  # first one's data.
  if [[ -n "$DATA" ]]; then
    mkdir -p "$DATA"
    ai_env+=(PORTAL_DATA_DIR="$DATA")
    ok "database: $DATA"
  fi
  [[ -n "$UPGRADE_URL" ]] && ai_env+=(PORTAL_UPGRADE_URL="$UPGRADE_URL")
  if [[ "$WANT_AI" == 1 ]]; then
    # += , not = : this used to replace the array and threw away the database
    # setting above it
    ai_env+=(
      PORTAL_ASSISTANT_ENABLED=1
      PORTAL_ASSISTANT_PROVIDER=ollama
      PORTAL_ASSISTANT_URL="http://127.0.0.1:$OLLAMA_PORT"
      PORTAL_ASSISTANT_MODEL="$MODEL"
    )
  fi
  env "${ai_env[@]}" ./.venv/bin/uvicorn app.main:app \
      --host 127.0.0.1 --port "$PORT" --reload \
      > "$RUN/portal.log" 2>&1 &
  echo $! > "$RUN/$PORTAL_PID.pid"
  for _ in $(seq 40); do
    curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null && break
    sleep 0.5
  done
  if curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null; then
    ok "portal answering: $(curl -s "http://127.0.0.1:$PORT/healthz")"
    # read back with exactly the environment the server was given, so a
    # mistake in what was passed shows up here instead of being inferred later
    env "${ai_env[@]}" ./.venv/bin/python - <<'READBACK' 2>/dev/null || warn "could not read back the database path"
from app import db
print("  \u2713 database: %s" % db.FILE)
READBACK
  else
    warn "the portal did not come up — last lines of its log:"
    tail -20 "$RUN/portal.log" | sed 's/^/      /'
    exit 1
  fi
}

case "$CMD" in
  up)
    start_model
    start_portal
    echo
    if alive "$PORTAL_PID"; then
      say "ready"
    else
      say "the model is ready; the portal is NOT running from this script"
    fi
    echo "    portal     http://127.0.0.1:$PORT"
    if [[ "$WANT_AI" == 1 ]]; then
      echo "    assistant  $MODEL via http://127.0.0.1:$OLLAMA_PORT"
      echo "               (Settings shows it as supplied by the deployment;"
      echo "                saving anything there overrides it)"
    fi
    echo "    logs       scripts/dev.sh logs"
    echo "    stop       scripts/dev.sh stop"
    ;;
  status)
    say "portal"
    if listening "$PORT"; then
      echo "    $(curl -s "http://127.0.0.1:$PORT/healthz" 2>/dev/null || echo 'port open, not answering /healthz')"
      alive "$PORTAL_PID" && echo "    started by this script (pid $(cat "$RUN/$PORTAL_PID.pid"))" \
                   || echo "    started outside this script"
    else
      echo "    not running"
    fi
    say "model"
    if curl -sf "http://127.0.0.1:$OLLAMA_PORT/api/tags" >/dev/null 2>&1; then
      curl -s "http://127.0.0.1:$OLLAMA_PORT/api/tags" | python3 -c '
import json, sys
models = json.load(sys.stdin).get("models") or []
for m in models:
    gb = round(m.get("size", 0) / 1e9, 1)
    print("    " + m["name"] + "  " + str(gb) + " GB")
if not models:
    print("    serving, but no model downloaded yet")'
      alive ollama && echo "    native, started by this script"
      docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$CONTAINER" \
        && echo "    Docker container $CONTAINER"
      alive portforward && echo "    port-forward to a cluster"
    else
      echo "    nothing on $OLLAMA_PORT"
    fi
    ;;
  stop)
    stop_pid "$PORTAL_PID" "the portal on $PORT"
    # The model is shared. Stopping one instance must not take the assistant
    # away from another one that is still running, so it is only stopped when
    # this was the last portal.
    # portal*.pid, not portal-*.pid: instances started before the pidfile became
    # per-port are recorded as plain portal.pid, and the narrower glob missed
    # them — stopping one instance then took the model away from a portal that
    # was still serving, which is the exact thing this guard exists to prevent
    others=0
    for f in "$RUN"/portal*.pid; do
      [[ -f "$f" ]] || continue
      [[ "$f" == "$RUN/$PORTAL_PID.pid" ]] && continue
      kill -0 "$(cat "$f")" 2>/dev/null && others=$((others + 1))
    done
    if [[ "$others" -gt 0 ]]; then
      warn "$others other portal instance(s) still running — leaving the model up"
      exit 0
    fi
    stop_pid portforward "the cluster port-forward"
    stop_pid ollama "the native Ollama"
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$CONTAINER"; then
      docker stop "$CONTAINER" >/dev/null && ok "stopped the Ollama container"
      echo "    (its model volume is kept — nothing to re-download)"
    fi
    ;;
  logs)
    tail -f "$RUN/portal.log"
    ;;
esac
