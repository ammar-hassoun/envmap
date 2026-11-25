#!/usr/bin/env bash
#
# Privileged Access, end to end, against REAL servers in Docker.
#
#   scripts/pam-e2e.sh                   # start the rig, run the checks, tear down
#   scripts/pam-e2e.sh --only ssh,vnc    # only sections whose names start so
#   scripts/pam-e2e.sh --keep            # leave the rig running afterwards
#
#   --ssh-port 12222   --guacd-port 14822    host ports, if those are taken
#
# WHAT IT STARTS, on a private network, every container named pam-e2e-*:
#   ssh    OpenSSH, with a throwaway key AND a password account, so both of
#          the credential paths the broker has are driven for real
#   guacd  the image the chart ships, with the run's data directory mounted at
#          the SAME path -- guacd writes each recording where the portal files
#          it, exactly as the sidecar does inside the pod
#   vnc    Xvfb + x11vnc showing a clock, so "idle" is judged against a screen
#          that never stops changing
#   rdp    xrdp + xorgxrdp, the same clock
#
# Then it runs tests/e2e_pam.py against them: a real uvicorn, real websockets,
# the ssh and sftp binaries, guacd. See that file for what it proves.
#
# WHAT IT NEVER DOES
#   Every credential is generated for the run and dies with it. Nothing but the
#   pam-e2e-* containers, their network and one temporary directory is touched,
#   and all three are removed at the end unless --keep is given -- except that
#   a FAILED run keeps its directory (the portal's log and every recording), so
#   there is something to read. The first run pulls about 2 GB of images; they
#   stay, so later runs start in seconds. `docker image rm` them to reclaim it.
set -euo pipefail
cd "$(dirname "$0")/.."

ONLY=""
KEEP=0
SSH_PORT=12222
GUACD_PORT=14822
NET="pam-e2e-net"
SSH_IMAGE="${PAM_E2E_SSH_IMAGE:-lscr.io/linuxserver/openssh-server:latest}"
GUACD_IMAGE="${PAM_E2E_GUACD_IMAGE:-guacamole/guacd:1.6.0}"
DESK_IMAGE="${PAM_E2E_DESK_IMAGE:-alpine:3.20}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --only) ONLY="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --ssh-port) SSH_PORT="$2"; shift 2 ;;
    --guacd-port) GUACD_PORT="$2"; shift 2 ;;
    -h|--help) sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m  !\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m  ✓\033[0m %s\n' "$*"; }

[[ -x .venv/bin/python ]] || { warn "no .venv here -- create it first"; exit 2; }
docker info >/dev/null 2>&1 || { warn "Docker is not running"; exit 2; }

# A resolved path, because guacd is handed the path the PORTAL computes and
# must find the same directory at it: /var/folders and /private/var/folders
# are one place on a Mac and two strings to a bind mount.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/pam-e2e.XXXXXX")"
WORK="$(cd "$WORK" && pwd -P)"
CONTAINERS=(pam-e2e-ssh pam-e2e-guacd pam-e2e-vnc pam-e2e-rdp)
RC=1

teardown() {
  if [[ $KEEP -eq 1 ]]; then
    warn "left running: ${CONTAINERS[*]} (network $NET); data in $WORK"
    return
  fi
  docker rm -f "${CONTAINERS[@]}" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  if [[ $RC -eq 0 ]]; then
    rm -rf "$WORK"
  else
    warn "kept the failed run's directory: $WORK"
  fi
}
trap teardown EXIT

rand() { openssl rand -hex 12; }
SSH_PW="$(rand)"; VNC_PW="$(rand | cut -c1-8)"; RDP_PW="$(rand)"
ssh-keygen -q -t ed25519 -N '' -C pam-e2e -f "$WORK/id"

say "starting the rig"
docker rm -f "${CONTAINERS[@]}" >/dev/null 2>&1 || true
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create "$NET" >/dev/null

# The ssh server is started by a script of its own, because the host-key
# checks REPLACE it mid-run: a fresh container generates a fresh host key,
# which is the change the portal has to refuse.
cat > "$WORK/ssh-up.sh" <<EOF
#!/bin/sh
docker rm -f pam-e2e-ssh >/dev/null 2>&1
exec docker run -d --name pam-e2e-ssh --network $NET \\
  -p 127.0.0.1:$SSH_PORT:2222 \\
  -e PUID=1000 -e PGID=1000 -e TZ=Etc/UTC -e USER_NAME=pamuser \\
  -e PASSWORD_ACCESS=true -e USER_PASSWORD=$SSH_PW \\
  -e PUBLIC_KEY="\$(cat '$WORK/id.pub')" $SSH_IMAGE
EOF
chmod 700 "$WORK/ssh-up.sh"
"$WORK/ssh-up.sh" >/dev/null

# guacd AS THE POD RUNS IT: a uid the image has no passwd entry for, a
# read-only root, and HOME on a writable mount. Run as the image's own user it
# passes checks the shipped sidecar fails -- which is how every RDP target
# came to die in the TLS handshake with nothing here noticing.
docker run -d --name pam-e2e-guacd --network "$NET" \
  -p "127.0.0.1:$GUACD_PORT:4822" --user "$(id -u):$(id -g)" \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /home/guacd:rw,mode=1777 -e HOME=/home/guacd \
  -v "$WORK:$WORK" "$GUACD_IMAGE" >/dev/null

CLOCK='while true; do date; sleep 1; done'
docker run -d --name pam-e2e-vnc --network "$NET" "$DESK_IMAGE" sh -c "
  apk add --no-cache xvfb x11vnc xterm font-misc-misc >/dev/null 2>&1
  (Xvfb :0 -screen 0 1280x800x24 >/dev/null 2>&1 &); sleep 2
  (DISPLAY=:0 xterm -geometry 90x25+30+30 -e sh -c '$CLOCK' &)
  exec x11vnc -display :0 -forever -shared -passwd $VNC_PW -rfbport 5900 -quiet
" >/dev/null

docker run -d --name pam-e2e-rdp --network "$NET" "$DESK_IMAGE" sh -c "
  apk add --no-cache xrdp xorgxrdp xorg-server xterm font-misc-misc dbus-x11 \
    openssl >/var/log/apk.log 2>&1 || { cat /var/log/apk.log; exit 1; }
  adduser -D -s /bin/sh rdpuser && echo 'rdpuser:$RDP_PW' | chpasswd
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=pam-e2e-rdp \
    -keyout /etc/xrdp/key.pem -out /etc/xrdp/cert.pem >/dev/null 2>&1
  printf '#!/bin/sh\nexec xterm -geometry 90x25+30+30 -e sh -c \"$CLOCK\"\n' \
    > /etc/xrdp/startwm.sh && chmod 755 /etc/xrdp/startwm.sh
  mkdir -p /var/run/xrdp
  xrdp-sesman --nodaemon & exec xrdp --nodaemon
" >/dev/null

wait_for() {                     # wait_for <label> <seconds> <container> <cmd…>
  local label=$1 secs=$2 box=$3; shift 3
  local end=$(( $(date +%s) + secs ))
  until "$@" >/dev/null 2>&1; do
    if (( $(date +%s) >= end )); then
      warn "$label did not come up in ${secs}s; its last words:"
      docker logs --tail 20 "$box" 2>&1 | sed 's/^/      /'
      exit 1
    fi
    sleep 2
  done
  ok "$label"
}
wait_for "ssh on 127.0.0.1:$SSH_PORT" 120 pam-e2e-ssh \
  ssh -i "$WORK/id" -p "$SSH_PORT" -o BatchMode=yes -o ConnectTimeout=3 \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      pamuser@127.0.0.1 true
wait_for "guacd on 127.0.0.1:$GUACD_PORT" 60 pam-e2e-guacd \
  nc -z 127.0.0.1 "$GUACD_PORT"
wait_for "vnc desktop" 300 pam-e2e-vnc docker exec pam-e2e-vnc nc -z 127.0.0.1 5900
wait_for "rdp desktop" 600 pam-e2e-rdp docker exec pam-e2e-rdp nc -z 127.0.0.1 3389

say "running tests/e2e_pam.py"
export PAM_E2E_DATA="$WORK/data" \
  PAM_E2E_SSH_HOST=127.0.0.1 PAM_E2E_SSH_PORT="$SSH_PORT" \
  PAM_E2E_SSH_USER=pamuser PAM_E2E_SSH_KEY="$WORK/id" \
  PAM_E2E_SSH_PASSWORD="$SSH_PW" PAM_E2E_SSH_ROTATE="$WORK/ssh-up.sh" \
  PAM_E2E_GUACD="127.0.0.1:$GUACD_PORT" \
  PAM_E2E_VNC=pam-e2e-vnc:5900 PAM_E2E_VNC_PASSWORD="$VNC_PW" \
  PAM_E2E_RDP=pam-e2e-rdp:3389 PAM_E2E_RDP_USER=rdpuser \
  PAM_E2E_RDP_PASSWORD="$RDP_PW" PAM_E2E_ONLY="$ONLY"
set +e
./.venv/bin/python -u tests/e2e_pam.py
RC=$?
set -e
exit $RC
