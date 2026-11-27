#!/bin/bash
# OpenSSH interop test for libpqvault-sk.so against a simulated phone, in a private namespace.
# No root, and neither the system sshd nor ~/.ssh is touched.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
DESKTOP=$(dirname "$HERE")
LIB=$DESKTOP/build/native/libpqvault-sk.so
HELPER=$DESKTOP/build/loopback/pqvault-loopback-helper

if [ -z "${PQVAULT_INTEROP_INSIDE:-}" ]; then
    make -s -C "$DESKTOP/native" || exit 1
    "$DESKTOP/../gradlew" -q -p "$DESKTOP" loopbackHelper || exit 1
    exec unshare -U --map-current-user --keep-caps -n env PQVAULT_INTEROP_INSIDE=1 "$0" "$@"
fi

RUN=$(mktemp -d)
trap 'kill "$SSHD" 2>/dev/null; rm -rf "$RUN"' EXIT
ip link set lo up
SSHD_BIN=$(command -v sshd || echo /usr/sbin/sshd)
PASS=0
FAIL=0
pass() { echo "PASS $*"; PASS=$((PASS + 1)); }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
phone() { printf 'uv=%s\nuser=%s\nforge=%s\n' "$1" "$2" "${3:-no}" > "$RUN/mode"; }

ssh-keygen -q -t ed25519 -N '' -f "$RUN/host_ed25519"
: > "$RUN/authorized_keys"
cat > "$RUN/sshd_config" <<CONFIG
Port 2222
ListenAddress 127.0.0.1
HostKey $RUN/host_ed25519
PidFile $RUN/sshd.pid
AuthorizedKeysFile $RUN/authorized_keys
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
PubkeyAcceptedAlgorithms sk-ecdsa-sha2-nistp256@openssh.com,sk-ssh-ed25519@openssh.com
LogLevel DEBUG1
CONFIG
"$SSHD_BIN" -D -e -f "$RUN/sshd_config" 2> "$RUN/sshd.log" &
SSHD=$!
for _ in $(seq 50); do grep -q "Server listening" "$RUN/sshd.log" 2>/dev/null && break; sleep 0.1; done
echo "[127.0.0.1]:2222 $(cut -d' ' -f1,2 "$RUN/host_ed25519.pub")" > "$RUN/known_hosts"
cat > "$RUN/ssh_config" <<CONFIG
Host bench
  HostName 127.0.0.1
  Port 2222
  User $(id -un)
  UserKnownHostsFile $RUN/known_hosts
  GlobalKnownHostsFile /dev/null
  StrictHostKeyChecking yes
  IdentitiesOnly yes
  IdentityAgent none
  BatchMode yes
CONFIG

export PQVAULT_SK_HELPER=$HELPER PQVAULT_LOOPBACK_DIR=$RUN SSH_SK_PROVIDER=$LIB
unset SSH_AUTH_SOCK
login() {
    [ -f "$1" ] || return 1
    timeout 60 ssh -F "$RUN/ssh_config" -o SecurityKeyProvider="${2:-$LIB}" -i "$1" bench 'echo LOGIN-OK' \
        2> "$RUN/ssh.err" | grep -q LOGIN-OK
}
keygen() { timeout 60 ssh-keygen -q -w "$LIB" -N '' "$@" > "$RUN/keygen.out" 2>&1; }

phone available verify
if keygen -t ecdsa-sk -C interop1 -f "$RUN/k1"; then pass "ssh-keygen -t ecdsa-sk enrols"; else fail "ecdsa-sk enrolment"; fi
cat "$RUN/k1.pub" >> "$RUN/authorized_keys"
if login "$RUN/k1"; then pass "ssh login with ecdsa-sk"; else fail "ecdsa-sk login"; fi

if keygen -t ed25519-sk -C interop2 -O resident -O verify-required -O application=ssh:interop -O user=interop -f "$RUN/k2"; then
    pass "ssh-keygen -t ed25519-sk -O resident -O verify-required enrols"
else
    fail "ed25519-sk enrolment"
fi
echo "verify-required $(cat "$RUN/k2.pub")" >> "$RUN/authorized_keys"
if login "$RUN/k2"; then pass "ssh login with ed25519-sk under verify-required"; else fail "ed25519-sk login"; fi

mkdir "$RUN/download"
if (cd "$RUN/download" && timeout 60 ssh-keygen -q -K -w "$LIB" -N '' > "$RUN/keygen.out" 2>&1); then
    DOWNLOADED=$(find "$RUN/download" -name 'id_*_sk_rk*' ! -name '*.pub' | head -1)
    if [ -n "$DOWNLOADED" ] && login "$DOWNLOADED"; then
        pass "ssh-keygen -K downloads the resident key, which signs in"
    else
        fail "login with the downloaded key"
    fi
else
    fail "ssh-keygen -K"
fi

echo "pq-vault" > "$RUN/message"
echo "interop $(cut -d' ' -f1,2 "$RUN/k1.pub")" > "$RUN/allowed_signers"
if timeout 60 ssh-keygen -q -Y sign -f "$RUN/k1" -n file "$RUN/message" > "$RUN/keygen.out" 2>&1 &&
    ssh-keygen -q -Y verify -f "$RUN/allowed_signers" -I interop -n file -s "$RUN/message.sig" < "$RUN/message" > /dev/null 2>&1; then
    pass "ssh-keygen -Y sign and -Y verify"
else
    fail "SSH signature of a file"
fi

mkdir -p "$RUN/prefix/helper/bin"
cp "$LIB" "$RUN/prefix/libpqvault-sk.so"
cp "$HELPER" "$RUN/prefix/helper/bin/pqvault-ssh-helper"
if (unset PQVAULT_SK_HELPER; login "$RUN/k1" "$RUN/prefix/libpqvault-sk.so"); then
    pass "the library finds the helper installed next to it"
else
    fail "installed layout"
fi

phone unavailable verify
if login "$RUN/k1"; then fail "a phone without screen lock must not sign"; else pass "no screen lock on the phone: login refused"; fi
if keygen -t ecdsa-sk -f "$RUN/k3"; then fail "a phone without screen lock must not enrol"; else pass "no screen lock on the phone: enrolment refused"; fi
if (cd "$RUN/download" && timeout 60 ssh-keygen -q -K -w "$LIB" -N '' > "$RUN/keygen.out" 2>&1); then
    fail "a phone without screen lock must not send its keys"
else
    pass "no screen lock on the phone: ssh-keygen -K refused"
fi

phone available reject
if login "$RUN/k1"; then fail "a refused request must not sign"; else pass "refused on the phone: login refused"; fi

phone available verify yes
if login "$RUN/k1"; then fail "an unverified signature must not reach sshd"; else pass "a signature without user verification is dropped"; fi

phone available verify
if login "$RUN/k1"; then pass "the key still works afterwards"; else fail "login after the refusals"; fi

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
