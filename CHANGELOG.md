## [2.0.0](https://github.com/Simthem/webauthn-kotlin/compare/v1.1.3...v2.0.0) (2026-09-04)

The repository becomes **PQ Vault**, an Android passkey manager whose vault is synced to a
WebDAV server you own. The upstream library is kept intact in the `:webauthn` module but
is no longer what the project builds.

**Breaking.** Upstream stores every passkey as a non-exportable `AndroidKeyStore` key, so
nothing can be backed up or moved to another phone. PQ Vault holds software keys inside an
encrypted file instead. The two models are incompatible: credentials created with
`:webauthn` cannot be imported, and there is no migration path. The reasoning is in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

### Added

**Vault core (`:vault`, pure Kotlin, no Android dependency)**

- `.pqvault` file format: cleartext header authenticated as AAD, XChaCha20-Poly1305
  content, detached signature.
- Argon2id key derivation (64 MiB, 3 passes) from the user passphrase.
- Hybrid X25519 with ML-KEM-768 key wrapping, so the vault key can be handed to a second
  device without a long-lived classical secret on the server.
- Hybrid Ed25519 with ML-DSA-65 file signature.
- Software WebAuthn authenticator: COSE keys, `authenticatorData`, and an algorithm
  negotiation that offers ML-DSA and falls back to ES256.
- WebDAV sync engine with replay and rollback protection, plus a merge that keeps the
  additions of two devices that both worked offline instead of overwriting one of them.
- caBLE hybrid transport: FIDO QR parsing, Noise handshake, CTAP2 codec.

**Android application (`:app`)**

- `CredentialProviderService`, so passkeys are offered in the browser and in other apps,
  not only inside PQ Vault (Android 14 and later).
- Caller verification against Digital Asset Links, with a trusted-browser list.
- FIDO QR scanner and encrypted BLE proximity advertising, acting as a nearby
  authenticator with no dependency on Google Play services.
- Second-device pairing by QR code, enrolling that device as a vault recipient.
- OkHttp WebDAV client and a periodic `WorkManager` sync, with notifications raised when
  the server returns a stale or tampered vault.
- Biometric unlock and automatic locking after idle time.
- Compose interface, in English and French, following the system language.

**Development harness (`:rptest`)**

- A minimal relying party that requests a passkey, for exercising the provider end to end.

**Build and CI**

- `./gradlew verify` and `./gradlew testAll`, matching exactly what CI runs, so the two
  cannot drift.
- GitHub Actions and GitLab pipelines running the same checks: Gradle wrapper checksum,
  the 91 unit tests, Android Lint over both modules with SARIF output, CodeQL, Snyk,
  OSV-Scanner, Gitleaks, Trivy and dependency review.
- A release signing check asserting the APK comes out unsigned when no keystore is
  configured, so it can never quietly inherit the debug key.
- Dependabot, grouped by dependency family.

**Documentation**

- README rewritten for the application: build, install, Nextcloud setup, security model,
  troubleshooting and known limitations.
- `docs/ARCHITECTURE.md`: file format, threat model, merge logic, and why post-quantum
  belongs in some layers and not others.
- `docs/UPSTREAM-LIBRARY.md`: the original library README, preserved.

### Changed

- Project identity is now the fork's own: `rootProject.name` is `pqvault` and the Gradle
  group is `com.pqvault`, in place of `webauthn-kotlin` and `com.linecorp`.
- `CONTRIBUTING.md` rewritten for this repository. It pointed at the upstream issue
  tracker and asked contributors to sign LY Corporation's ICLA, for work that does not go
  to LY Corporation.
- Gradle wrapper pinned by SHA-256, with `validateDistributionUrl` enabled and a network
  timeout set.
- `.gitignore` extended to cover per-module `build/` directories, `.kotlin/`, APK and AAB
  outputs, and signing material. Only the root `build/` was ignored before, which left
  several thousand build artifacts visible to `git add`.
- Android Lint publishes only its errors to the code-scanning view. Warnings stay in the
  full report, uploaded as an artifact. Listing "a newer version of camera-view is
  available" beside a hardcoded secret, at the same weight, makes the list unreadable
  rather than anyone safer.

### Removed

- Maven Central publishing, in full: the `gradle-nexus.publish-plugin` and its
  `nexusPublishing` block, the `maven-publish` and `signing` setup in `:webauthn`, the
  sources and javadoc jar tasks, and `.github/workflows/publish.yml`. The project ships an
  application, not a library. The workflow also fired on every push to `main` and tried to
  publish upstream's unchanged code under `com.linecorp`, which is not this project's
  namespace.
- The `pom.*` properties in `gradle.properties`. No `.gradle` file read them: `:webauthn`
  hardcoded its own coordinates, so they had been stale metadata for some time.
- The `versionMajor`, `versionMinor`, `versionPatch` and `snapshotBuild` properties, which
  existed only to name the published artifact. The version now lives in
  `app/build.gradle`, next to `versionCode`.

### Security

- User verification before a hybrid signature is now bound to the Android Keystore.
  `HybridUserVerification` used to release a WebAuthn assertion on the strength of
  `BiometricPrompt`'s success callback, which a rooted device can invoke without anyone
  touching the sensor. It now carries a `CryptoObject` over a key created with
  `setUserAuthenticationRequired` and a zero-second validity window, and answers
  `Verified` only after that key has actually encrypted something. This is the guarantee
  `BiometricVaultLock` already relied on, applied to the second place that needed it.
- Every third-party GitHub Action is pinned to a full commit SHA rather than a moving
  tag, `snyk/actions/setup` included, which was tracking a branch. A tag can be repointed
  by whoever owns the action, and it runs on the runner with the workflow's token.
- Backup is disabled in the `rptest` harness, which was inheriting the platform default
  of allowing it.
- Release builds are signed only when a keystore is configured through `pqvaultStoreFile`
  or `PQVAULT_STORE_FILE`. Without it the APK is left unsigned and the build says so: for
  a credential provider the signing certificate is the app's identity.
- Passkey signatures stay ES256. The algorithm is chosen by each site through
  `pubKeyCredParams`, and no relying party can verify ML-DSA today. Post-quantum is
  applied where it changes the outcome, meaning the key material that sits on a server for
  years.

## 1.1.3 (2025-09-16)

### Changed
- Remove Gson dependency and migrate to kotlinx.serialization for JSON handling
- Update biometric library version from alpha to stable (1.2.0-alpha05 → 1.1.0)

## 1.1.2 (2025-09-09)

### Changed
- Fix build issue from v1.1.1
 
## 1.1.1 (2025-09-08)

### Changed
- Remove unnecessary permissions (USE_FINGERPRINT) from the manifest file.
