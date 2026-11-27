# PQ Vault: architecture and security model

An Android passkey manager synced over WebDAV (Nextcloud), following the KeePassDX model
applied to passkeys rather than passwords.

## Why a deep fork and not just an update

The upstream library (`line/webauthn-kotlin`) generates every private key inside the
`AndroidKeyStore`. Those keys are **non-exportable by hardware design**: they never leave
the TEE or StrongBox. What the database stores is therefore only metadata (`rpId`,
`credentialId`, `userHandle`, `aaguid`) plus a counter.

The consequence is that syncing that database syncs **no keys at all**. Restored on
another phone, every passkey fails. A syncable vault requires software keys. That is the
central trade of this project, and the same one KeePass made.

## Where post-quantum belongs, and where it does not

| Layer | Algorithm | Post-quantum |
|---|---|---|
| Passkey and SSH key signature | ES256 (P-256), Ed25519 | **No, dictated by the site** |
| Vault at rest | Argon2id, XChaCha20-Poly1305 | **Resistant, as strong as the passphrase** |
| Multi-device key wrapping | X25519 + ML-KEM-768 (hybrid) | **Yes, real gain** |
| Vault file signature | Ed25519 + ML-DSA-65 (hybrid) | **Yes, real gain** |

**The passkey signature cannot be post-quantum.** The algorithm is negotiated by the
relying party through `pubKeyCredParams`: the site decides. The COSE identifiers for
ML-DSA are registered with IANA (ML-DSA-44 = -48, -65 = -49, -87 = -50), but no site
verifies them today. Signing with ML-DSA would produce a passkey nobody can validate.
`SoftwareAuthenticator.selectAlgorithm()` picks ES256, or Ed25519 when a client offers only
that.

**The vault at rest needs no post-quantum algorithm.** Its key is symmetric and derived
from the passphrase. Grover's algorithm only gives a quadratic speedup, so 256 bits still
leaves about 128 bits post-quantum, and there is no RSA or ECDH to break. That bound is the
key's, not the vault's: an attacker with the file guesses passphrases, so the real margin is
the passphrase's entropy times the Argon2id cost, and it also rests on the implementations
of Argon2id, XChaCha20-Poly1305 and the code around them being correct.

**Post-quantum becomes useful as soon as asymmetric cryptography appears.** Enrolling a
second device wraps the vault key to its public key. That wrapped copy sits on Nextcloud
for years, which is the textbook harvest-now-decrypt-later target. Hence ML-KEM-768, in
hybrid: if X25519 or the lattice falls, the other half still holds.

## The `.pqvault` file format

```
magic[8] = "PQVAULT1"
u32 headerLength  | header    (cleartext JSON, authenticated as AAD)
u32 contentLength | content   (XChaCha20-Poly1305)
u32 sigLength     | signature (Ed25519 then ML-DSA-65)
```

The header stays readable without the passphrase (KDF parameters, recipients) but serves
as additional data for the content cipher: modifying it makes the content fail to decrypt
rather than allowing a silent downgrade.

`formatVersion` is 1 for a vault any release can handle. As soon as the vault holds
something an older release would mishandle, the header lists it in `features` and the
file becomes version 2, which releases before 2.2.0 refuse as an unsupported format:

- `ssh-credentials`: an OpenSSH key. Older releases do not require verification for it and
  drop its `credProtect` level when they rewrite the vault.
- `device-revocation`: revoked devices, a signing key chain or exposed credentials. Older
  releases would drop them on rewrite and let a revoked device back in.

A reader refuses a version 2 file listing a feature it does not know.

### Recipients

The vault master key (VMK) encrypts the content exactly once; each recipient holds its own
wrapped copy. That is what allows a device to be enrolled **without giving it the
passphrase**.

A device that has unlocked the vault once holds the VMK and the signing private key, so
dropping its recipient alone would revoke nothing. `revokeDevice` therefore rotates both,
and needs the passphrase to do it:

1. A new VMK is wrapped for the passphrase recipient (same Argon2id cost, new salt) and for
   each remaining device recipient. The revoked device gets no copy.
2. A new signing key pair replaces the old one. The old key signs
   `"pqvault/signing-key-rotation/v1" | old public key | new public key`, and the link joins
   `signingKeyChain` in the header (at most 16 links, oldest dropped).
3. The device goes into `revokedDevices` in the content. A merge drops any device record
   and recipient it matches, unless the same key was enrolled again afterwards.
4. Every credential gets `exposedAt`. A merge keeps the earliest value, so no older copy
   can clear it.

A client pinned to an older key accepts the vault only through an unbroken run of links
from its pinned key, each signed by the key it retires, and pins the new key once a sync
has uploaded or read it. A sync whose remote copy descends from the local key takes over
the remote keys and recipients. A local rotation not yet pushed keeps its keys and merges
the remote content. Any other signer is refused.

What rotation cannot undo: the revoked device keeps every credential it already synced and
its WebDAV app password. The credentials are marked exposed and have to be replaced at each
site (SSH keys removed from `authorized_keys`), and the app password revoked in Nextcloud.
A device that has not synced since the revocation trusts the first successor of the old key
it sees, and the revoked device holds that old key, so the other devices should sync before
it can reach the server.

- `passphrase`: Argon2id(passphrase, salt) produces a KEK that wraps the VMK
- `device`: hybrid KEM to the device's public key
- *biometric*: **never in the file**. Purely local, the VMK is wrapped by a Keystore AES
  key gated on a fingerprint. It is a local unlock shortcut on that phone, not a portable
  access right.

### Replay protection

A malicious WebDAV server can serve back an **older but genuine version**: it decrypts and
verifies perfectly. Only two mechanisms detect it:

1. `vaultVersion`, a monotonic counter, refused if it goes backwards
2. the signing key **pinned on first open** (trust on first use). Without pinning,
   verifying a signature against a key the attacker also supplied proves nothing.

## Synchronisation

Optimistic concurrency rather than WebDAV `LOCK` (Nextcloud support is inconsistent, and a
lock held by a phone that lost signal would strand the vault). Every write carries an
`If-Match` for the exact version it merged against; a 412 triggers a re-read, a re-merge
and another attempt.

Merging happens **per entry, not per file**: two offline phones each hold a legitimately
newer file, and picking a winner would lose passkeys.

- an entry present on both sides: the more recently updated (`updatedAt`) wins
- **`signCount` takes the maximum of both sides**, never the winner's value: a counter
  going backwards is read by sites as a cloned authenticator
- deletions are materialised as tombstones, otherwise they undo themselves

## Caller verification

The `origin` written into `clientDataJSON` is what binds an assertion to the site it was
meant for. Computing it carelessly defeats the main protection passkeys provide.

- **Native app**: the origin derives from its own signature,
  `android:apk-key-hash:<base64url SHA-256 of the certificate>`. It is then checked against
  `https://<rpId>/.well-known/assetlinks.json`: a site declares the packages it recognises,
  and an app absent from that list is refused.
- **Browser**: it declares a web origin itself, which can only be believed if the user has
  trusted it, verified by package **and** signature. Nothing trusted means every
  web-origin request is refused. **We fail closed**: on a de-Googled phone, no implicit
  trust ships with the app.

The trusted browser list is built from the installed packages, with fingerprints read from
the APKs on the device. Asking a user to hand-write Google's privileged-app JSON, with
fingerprints extracted through keytool, would guarantee nobody ever configures it.

The app's cryptographic identity and the site's authorisation of that app are separate
guarantees, and only `assetlinks.json` gives the second one:

| Statement file | Decision |
|---|---|
| Lists the app | Allowed |
| Does not list it, 404 or 410, other 4xx, a redirect | Refused |
| Malformed, empty or larger than 512 KB | Refused |
| TLS failure | Refused |
| Unreachable (network error, 5xx, 408, 429), association verified online in the last 7 days | Allowed, for an existing passkey only |
| Unreachable, never verified or verified longer ago | Refused |

The record of verified associations survives restarts and stores SHA-256 digests rather
than the site and package names. An explicit refusal erases it.

## Device identity and background sync

Merging requires opening the **remote** vault. Asking for the passphrase every fifteen
minutes is not synchronisation, and caching it would be worse. So the device enrolls itself
as a recipient, exactly as a second phone would, and decrypts its own copy of the vault key
through its hybrid KEM.

Its private key is sealed under a Keystore key that is deliberately **not** biometric
gated: a worker running with the screen off cannot show a fingerprint prompt. That is
genuinely less protection than the biometric path. A device whose sync key is compromised
is revoked from another device like a lost one.

`VaultSyncWorker` runs every 15 minutes (WorkManager's floor) under a network constraint. A
refused remote vault returns `failure()` rather than `retry()`: it is never a transient
error, and retrying would only hammer a server that is lying to us.

## Pairing

The QR code carries the server settings and the pinned signing key, with a five-minute
expiry. It deliberately does **not** carry the passphrase: photographing the screen over
someone's shoulder must not grant vault access. What it saves is the tedious part, a long
WebDAV URL and a 40-character app password typed on a phone keyboard.

The scanner uses zxing rather than ML Kit, which depends on Google Play services and is
precisely what is missing on a de-Googled phone. The luminance plane is copied row by row
because `rowStride` often exceeds the image width; reading it as one block shears every row
and makes scanning fail on exactly the devices that pad.

## Cross-device WebAuthn

The QR scanner in the vault header has a different job from device pairing. It consumes
the standard `FIDO:/` code produced by a browser when the user chooses a nearby phone or
tablet. Android's credential-provider service only receives requests made on the same
Android device, so this path implements the hybrid authenticator protocol itself.

The transaction has five authenticated stages:

1. Decode the decimal QR encoding and its CBOR map, including the desktop's compressed
   P-256 identity and the 16-byte one-time secret.
2. Derive a tunnel ID and connect to `wss://cable.ua5v.com` with the `fido.cable`
   subprotocol. The server returns a three-byte routing ID.
3. Place that routing ID and a random nonce in a 16-byte proximity message, encrypt it
   with AES-256 and authenticate it with a truncated HMAC. Android advertises the result
   under BLE service UUID `0xfff9`.
4. Derive the PSK from both the QR secret and the plaintext proximity message, then answer
   the desktop's `Noise_KNpsk0_P256_AESGCM_SHA256` handshake. The tunnel service cannot
   derive the traffic keys.
5. Exchange padded, AES-GCM-protected CTAP2 `makeCredential` or `getAssertion` messages.
   PQ Vault displays the relying-party ID and account, and releases a result only after
   explicit approval. Requests for CTAP user verification trigger Android's secure
   screen-lock prompt.

The tunnel is only a rendezvous relay. It receives the routing ID and ciphertext, but the
QR secret and BLE proof never reveal the CTAP request or the passkey signature to it. It
does see network metadata: both IP addresses, the tunnel and routing IDs, timing and
message sizes. Each
scan creates fresh traffic keys and the session expires after three minutes.

An Android intent filter for `fido:` is provided for camera apps that recognise the URI.
The embedded zxing scanner remains necessary because many camera and generic QR apps on
de-Googled systems display `FIDO:/...` as inert text instead of offering PQ Vault.

## OpenSSH security keys

OpenSSH's `sk-ecdsa-sha2-nistp256@openssh.com` and `sk-ssh-ed25519@openssh.com` keys are
FIDO credentials whose relying party ID is an application string starting with `ssh:`.
The computer sends ordinary CTAP2 `makeCredential` and `getAssertion` requests over the
hybrid tunnel, with `SHA-256(challenge)` or `SHA-256(signed data)` as the client data
hash. `sshd` rebuilds `SHA-256(application) | flags | counter | SHA-256(data)` and checks
the signature over it, which is exactly the authenticator data and client data hash a
WebAuthn assertion signs.

What OpenSSH needs beyond the website flow:

- **Ed25519** (COSE -8, OKP key) for `ed25519-sk`. ES256 stays the choice whenever a
  client offers it, so website passkeys keep working on older releases.
- **credProtect.** `ssh-keygen` refuses to create a resident or `verify-required` key on
  an authenticator that does not advertise it. The level is stored on the entry and
  enforced at signing time.
- **A `packed` self-attestation.** libfido2 verifies the attestation statement of every
  new credential and rejects `none`. The new key signs its own authenticator data, with
  no certificate. Websites still get `none`.
- **Exact extensions.** libfido2 rejects a credential whose authenticator data carries an
  extension output that was not requested, or lacks one that was.
- **Silent probes.** `ssh-keygen -O resident` first asks with `"up": false` whether a key
  already exists. Such a request is answered "no credentials" without any prompt and
  never produces a signature.

The client data hash says nothing about the operation, so the Linux provider also sends
the bytes OpenSSH asked to sign in a `pqvault-ssh-context` getAssertion extension, which
never produces an output. The phone reads the operation from them only when their SHA-256
is the client data hash: a login and its user (`SSH_MSG_USERAUTH_REQUEST`), the server
host key of a `publickey-hostbound-v00@openssh.com` request, or an `SSHSIG` signature and
its namespace. Anything else is shown as unidentified. The server's name is never in the
signed data. The provider adds the command it was started by (`ssh` and its destination,
or only the program name), which the phone shows apart as not verified.

The rules live in `RemoteRequestPolicy`, in the `vault` module, so the app and the JVM
tests run the same code:

- Every request for an `ssh:` application requires user verification, whatever the client
  asked for. A phone that cannot verify refuses it before anything is shown, and after the
  prompt nothing is signed unless the Keystore-backed verification succeeded.
- An SSH key is non-resident unless the client asked for a resident key, so it is only
  used when the computer names its key handle.
- SSH keys and website passkeys never answer for each other. The Credential Manager
  provider refuses `ssh:` applications outright, both because they are not host names and
  through an explicit check, so no app or browser on the phone can obtain a signature that
  `sshd` would accept.

`OpenSshKeys` encodes the public key blob, the `SHA256:` fingerprint and the unencrypted
`openssh-key-v1` key file `ssh-keygen` writes for a security key. That file holds the
public key, the application, the flags and the credential ID as key handle. It is what
another computer needs to ask the phone for a signature and contains no private key.
Exported keys carry the user-presence and user-verification flags, so `ssh` asks for
verification explicitly.

## The Linux security key provider

`desktop/` lets the stock OpenSSH client reach the phone. OpenSSH loads
`libpqvault-sk.so` through `SecurityKeyProvider` (sk-api 10, OpenSSH 9.1 and later). The
library is deliberately thin: it starts the helper for each request, passes OpenSSH's
arguments over a socket pair and copies the answer back into OpenSSH's structures. It
parses nothing beyond bounded length-prefixed fields. It does not rely on the helper's own
timeouts either: every exchange has a 180-second deadline on the monotonic clock, waited on
with `poll`, after which the helper gets `SIGTERM`, then `SIGKILL` two seconds later, and is
always reaped.

The helper runs the computer's side of the hybrid transport: it shows the `FIDO:/` code on
the terminal, scans BlueZ over D-Bus for the advert, opens the tunnel, runs the Noise
initiator and sends one CTAP2 request. It compiles the `vault` module's sources rather
than depending on a copy, so the QR format (`FidoQrCode`), the advert (`HybridAdvert`), the
tunnel derivations (`CableTunnel`), Noise (`CableNoise`) and the CTAP2 checks
(`Ctap2Client`) are the code the phone runs or its exact counterpart, tested against each
other in the `vault` module.

`Ctap2Client` refuses any answer that is not for the requested application, lacks the
user-presence or user-verification flag, carries an unrequested extension, or whose
self-attestation does not verify with the new key. A phone that skipped verification, by
bug or by tampering, therefore produces nothing OpenSSH can use, on top of the phone's own
refusal.

`ssh-keygen -K` goes through PQ Vault's own CTAP command, `0x41` in the vendor range.
Standard CTAP credential management needs a PIN protocol that this transport has no use
for. The phone answers it only after the user approves and verifies, and only with the
resident SSH keys: application, credential ID, public key, user ID and credProtect level.
Website passkeys are never listed.

The provider needs no privilege: BlueZ lets any local user scan, the helper only listens
for adverts and never connects to the phone over Bluetooth, and everything installs under
the user's home, including a Java runtime trimmed with `jlink`. With no terminal, the code
is shown in a window, and on standard error when there is no display either.

## Interface

The palette comes from the Mantine dark scale, to match share.privcloud.fr: background
`#141517`, surfaces `#25262B`, borders `#373A40`, text `#C1C2C5`, amber accent `#FFC107`.
The theme is **dark by default** and does not follow the system: amber on near-black is the
identity, and the light scheme is only a fallback.

Android 15 enforces edge-to-edge: without `safeDrawingPadding()`, content slides under the
status bar.

Strings live in resources, English by default with a French translation in `values-fr`.

## Implementation details worth keeping

- **`bcprov-jdk15to18`, never `bcprov-jdk18on`**: the latter places ML-KEM in the
  `META-INF/versions/9/` overlay, which D8 and R8 silently drop, leaving ML-KEM missing at
  runtime. Verified: the classes are present in the APK's dex.
- **The provider capability strings are asymmetric.** Passwords use
  `android.credentials.TYPE_PASSWORD_CREDENTIAL`, but passkeys use
  `androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL`. The system matches that string against
  the requested type, so the wrong prefix means passkey requests are never routed to the
  app, with no error anywhere.
- **The credential flow must offer a passphrase fallback.** Relying on biometrics alone
  makes every passkey unusable from the system picker on a phone with no enrolled
  fingerprint, or after a new enrolment invalidates the key.
- **An unlock action answers the request itself.** When the vault is locked the
  provider returns an "Unlock PQ Vault" authentication action. Android launches it and
  does **not** query the provider again afterwards: the activity has to put the
  credential entries in its result with `setBeginGetCredentialResponse`, or the sheet
  says there is no sign-in information. `CredentialEntries` builds that list for both
  the service and the activity.
- **BE and BS flags** (`FLAG_BACKUP_ELIGIBLE`, `FLAG_BACKUP_STATE`) are always set: they
  tell the site this is a synced passkey. The upstream library could not honestly set them.
- **`setInvalidatedByBiometricEnrollment(true)`**: enrolling a new fingerprint destroys the
  biometric key. Intended, otherwise someone adding their finger to a stolen phone inherits
  the vault. The user falls back to the passphrase.
- **Never re-serialise after a sync.** `serialize()` increments the version. Writing
  anything other than the bytes actually uploaded leaves the local file ahead of the
  server, and the next sync diagnoses a rollback. `Outcome.Written` carries those bytes for
  this reason.
- **Failure permanence is a flag, not a string.** The sync worker decides whether to retry
  from `Outcome.Failed.permanent`. Inspecting a human-readable message would break the
  moment that message is translated.
- **Attestation is `none`.** A self-hosted vault has no manufacturer certificate chain.
  Sites demanding verifiable attestation will refuse us, which is correct. SSH keys get a
  self-signed `packed` statement instead, because libfido2 refuses `none`.
- **`jniLibs.useLegacyPackaging = true`.** Storing native libraries uncompressed for
  page-aligned mmap made AGP insert roughly 20 MB of zero padding into the APK to align
  50 KB of libraries. Compressing them removes the padding and costs nothing at that size.
- **Incremental builds can inflate the APK.** AGP patches the existing archive in place
  and may leave a hole the size of the previous `classes.dex`. A clean build produces a
  compact file; the shrinking itself is not at fault.
- **material-icons-extended is not a dependency.** It compiles about ten thousand icons in
  to serve the fifteen used. R8 strips them in release, but debug builds paid 60 MB of dex
  for it. The missing icons are hand-drawn vectors in `res/drawable`.

## What this trade-off costs

Software keys in a synced file mean a vault that is only worth its passphrase and the AEAD
around it. Someone who obtains the file **and** a weak passphrase obtains every passkey.
This is exactly the bargain KeePass users accept knowingly, but it must be chosen rather
than suffered. Use a long passphrase (diceware): it is the only thing standing between a
stolen file and your accounts.
