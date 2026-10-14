# Security Policy

PQ Vault holds passkeys and signs WebAuthn assertions for other people's accounts. A
vulnerability here can hand someone else a way into those accounts, so reports are
handled privately and before anything else.

## Supported Versions

Only the latest release receives security fixes. Older versions do not, and the fix for a
reported issue ships as a new release rather than as a patch to an old one.

| Version | Supported |
|---|---|
| 2.1.x | Yes |
| < 2.1 | No |

## Reporting a Vulnerability

Please do not open a public issue, pull request or discussion for a vulnerability. Until a
fix is released, the details would only help someone exploit it.

Report it privately instead, by either of these routes:

- [Open a private security advisory](https://github.com/Simthem/webauthn-kotlin/security/advisories/new)
  on GitHub. This is the preferred route: the report, the discussion and the fix stay in
  one private place, and a CVE can be requested from there.
- Write to [Simon Thémiot](mailto:simon.themiot@informatiquenevers.fr) if you cannot use
  GitHub.

A useful report says:

- which version and which Android version you tested,
- what an attacker needs beforehand (a malicious app installed, a hostile WebDAV server,
  physical access to an unlocked phone, a QR code shown to the user...),
- what they obtain, and the steps or a proof of concept that show it.

You will get an acknowledgement as soon as the report has been read, and news as the fix
progresses. Once a release contains the fix, the advisory is published with credit to the
reporter, unless they would rather stay anonymous.

## Scope

Most worth reporting:

- the vault file format, its encryption, signature, rollback and signer pinning (`vault/`),
- key derivation and the device and biometric unlock paths,
- the credential provider: caller verification, origin handling, Digital Asset Links,
  user verification (`app/.../provider/`),
- the FIDO hybrid (QR) transport, its tunnel and BLE proximity check,
- WebDAV sync and pairing codes, including what a hostile server can do,
- secrets reaching logs, backups or other apps.

Out of scope:

- the `webauthn/` module, the original LY Corporation library kept for reference and not
  built into the app. Report those upstream.
- `rptest/`, a development harness that is never shipped.
- attacks that need the vault passphrase, or a rooted or otherwise compromised phone with
  the vault already unlocked.
- findings from automated scanners with no demonstrated impact on PQ Vault.
