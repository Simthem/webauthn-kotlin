# PQ Vault security key provider for OpenSSH (Linux)

Lets the stock OpenSSH client on a Linux computer use the SSH keys held by PQ Vault on
your phone. `ssh` and `ssh-keygen` load it through `SecurityKeyProvider`. Each enrolment or
login shows a QR code in the terminal, PQ Vault scans it, proves over Bluetooth that the
phone is next to the computer, and answers through an end-to-end encrypted tunnel after
your fingerprint or screen lock.

It is optional and separate from the Android app: nothing in the app needs it, and it is
built on its own, without the Android SDK.

## What it guarantees

- **The private keys are never sent to the computer.** The provider receives public keys,
  key handles and signatures, nothing else. They do sync, inside the encrypted vault, to
  the other devices enrolled in it, like your passkeys.
- **Every signature needs user verification on the phone.** The provider asks for it on
  every request, whatever the key file says, and drops any answer that does not carry both
  the user-presence and user-verification flags. The phone refuses SSH requests when it has
  no secure screen lock. There is no PIN, no cached approval and no fallback.
- **The tunnel relay cannot read the requests.** The QR secret and the Bluetooth advert
  never reach it, and the CTAP messages travel inside a Noise channel only the two devices
  can open. It still sees network metadata: both IP addresses, when each request happens,
  the tunnel and routing identifiers, and the size of the encrypted messages.

## Requirements

| | |
|---|---|
| OpenSSH | 9.1 or later (security key API version 10): Debian 12 and Ubuntu 24.04 qualify, Ubuntu 22.04 (8.9) does not |
| Bluetooth | BlueZ with a powered adapter. Its default policy lets any local user scan, no group or root needed. |
| Network | HTTPS to `cable.ua5v.com`, the public relay hybrid authenticators use |
| Phone | PQ Vault 2.2.0 or later, with a fingerprint or a secure screen lock |
| Build | JDK 21, a C compiler and `make`. Nothing Java is needed at run time: the helper installs its own trimmed runtime. |

## Installing, without root

From this directory:

```bash
cd native
make install
```

That builds `libpqvault-sk.so` and the helper with its own Java runtime (about 70 MB in
all) and puts them in `~/.local/lib/pqvault-ssh` (`make install PREFIX=...` to change it,
`make uninstall` to remove it). The library only ever starts the helper installed next to it.

## Using it

Name the provider on the command that needs it rather than for every host, so a hardware
FIDO2 key keeps working through OpenSSH's built-in support:

```bash
PQSK=$HOME/.local/lib/pqvault-ssh/libpqvault-sk.so
ssh-keygen -w "$PQSK" -t ed25519-sk -O verify-required -C "pq-vault" -f ~/.ssh/id_ed25519_sk_pqvault
ssh -o SecurityKeyProvider="$PQSK" -i ~/.ssh/id_ed25519_sk_pqvault server.example
```

To keep it in `~/.ssh/config`, scope it to the hosts that use the PQ Vault key:

```
Host server.example
    IdentityFile ~/.ssh/id_ed25519_sk_pqvault
    IdentitiesOnly yes
    SecurityKeyProvider /home/you/.local/lib/pqvault-ssh/libpqvault-sk.so
```

A `SecurityKeyProvider` under `Host *`, or an exported `SSH_SK_PROVIDER`, would send every
security key to PQ Vault, a hardware key included. For Git signing, set it on the command
only: `SSH_SK_PROVIDER="$PQSK" git commit -S`.

The terminal then shows:

```
PQ Vault: scan this code to create the SSH key on your phone.
Open PQ Vault and tap the QR scanner above the passkey list.
(QR code)
Waiting for the phone over Bluetooth...
Phone found, connecting...
Approve on the phone with your fingerprint or screen lock.
Done.
```

Add the `.pub` file to the server's `authorized_keys`, prefixed with `verify-required` so
the server checks the verification too. `ssh` then works as with any security key: one QR
code and one approval per connection.

`ecdsa-sk`, `-O resident`, `-O application=ssh:name`, `-O user=name` and
`ssh-keygen -w "$PQSK" -Y sign` (Git commit signing) work the same way.

On another computer, `ssh-keygen -w "$PQSK" -K` downloads the resident keys: the phone shows
**Send your SSH keys to this computer?** with each fingerprint, and sends public keys and
key handles only, after your fingerprint or screen lock. **Export key file** on the phone
does the same for one key, resident or not.

Without a terminal, from `ssh-agent` or a graphical Git tool, the code appears in a small
window instead. `ssh-agent` only loads providers it was told to trust:

```bash
ssh-agent -P "$HOME/.local/lib/pqvault-ssh/*"
```

## Limits

- **Linux only.** The provider talks to BlueZ.
- **One code per operation.** Each login, signature or download shows a new QR code.

## How it fits together

```
ssh / ssh-keygen
  -> ssh-sk-helper (OpenSSH)
     -> libpqvault-sk.so          C, sk-api 10, moves bytes only
        -> pqvault-ssh-helper     JVM on its own runtime, one process per request
           QR code (zxing) on the terminal, or in a window
           Bluetooth advert      BlueZ over D-Bus, read-only scan
           tunnel                OkHttp WebSocket
           Noise and CTAP2       vault module, the same code as the app
```

The helper compiles the app's `vault` module sources directly: the QR format, the advert,
the Noise handshake, the CTAP2 messages and their checks are the code the phone runs, not
a copy of it.

## Tests

Three levels, which prove different things.

**1. Unit tests**, no device, from the repository root:

```bash
./gradlew -p desktop test
```

They include whole enrolments, logins and key downloads against a phone simulated with
the app's own code (QR parser, advert, Noise responder, CTAP decoder, `RemoteRequestPolicy`), with only
Bluetooth, the relay and the fingerprint prompt replaced in memory. They cover refusals:
no screen lock, a rejected request, an unknown key, and a phone that signs without
verifying. The protocol pieces shared with the app are tested in the `vault` module.

**2. OpenSSH interoperability**, no device, no root:

```bash
desktop/interop/openssh.sh
```

It runs the machine's own `ssh-keygen`, `ssh` and `sshd` against `libpqvault-sk.so`, with
the helper replaced by one that faces the simulated phone. Its `sshd` listens on
127.0.0.1:2222 inside a private user and network namespace and every file lives in a
temporary directory, so the system `sshd` and `~/.ssh` are never touched. It needs
unprivileged user namespaces.

**3. With a real phone.** Neither level above exercises Bluetooth, the public relay, the
camera or the biometric prompt. Until the steps below pass on real hardware, the hybrid
transport is not validated:

1. `ssh-keygen -t ed25519-sk -O verify-required` with the provider: the code appears,
   PQ Vault scans it, the computer finds the phone, the phone shows
   **Create an SSH key for ssh:?**, the fingerprint prompt follows, the key file is
   written.
2. A login to a server whose `authorized_keys` line starts with `verify-required`: the
   phone shows **Allow an SSH login?** with the fingerprint `ssh` printed, the user name
   read from the signed data, the server host key `ssh` accepted, and `ssh` with its
   destination marked as not verified.
3. The same with `-t ecdsa-sk` and with `-O resident`, then `ssh-keygen -K` on another
   computer: the phone lists the resident keys and the downloaded file signs in.
4. A login from a graphical Git tool or through `ssh-agent`: the code shows in a window.
5. Tapping **Reject** on the phone: `ssh` fails and nothing is signed.
6. A phone without a secure screen lock: enrolment and login are refused.
7. `git commit -S` with `gpg.format ssh`: the phone shows **Allow an SSH signature?** and
   **Git signature (namespace git)**.
8. Bluetooth off on the computer: the helper says no adapter is powered on.
9. Scanning the code with another app or from too far away: nothing connects and the
   request times out after about three minutes, and `ssh` returns even if the helper hangs.
