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
- CI covers every module rather than two. The unit test job adds `:webauthn`, Android
  Lint adds `:webauthn` and `:rptest`, and the CodeQL build compiles all four. The passkey
  authenticator and the relying-party harness were shipping without a single check running
  over them, which is the opposite of where the attention belongs.
- Android Lint emits SARIF from `:webauthn` and `:rptest` as well, and the GitHub job
  merges the three reports before filtering them down to errors. The GitLab artefact list
  already named those two files, which were never produced.
- GitLab jobs re-export the HTTP proxy at job runtime. A project or group variable
  outranks the pipeline's own `variables:` block, so a stale value there silently replaced
  the working tunnel and every job that reached the network failed on it.
- `getAllAccounts` returned every credential four times. It looped over both
  authentication methods and both attestation formats, and each of those four
  authenticators reads the single database it was handed. `deleteAllAccounts` had the same
  shape and, worse, removed the database rows while leaving the Keystore keys behind. It
  now deletes the key alongside each credential and takes the same lock as every other
  mutating operation.
- The two remaining deprecated framework calls in `:webauthn` carry an explicit
  suppression and the reason it is there. Both replacements need API 30 and the module
  still declares `minSdk 28`, so the suppressions say what has to change before the calls
  can go.

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

- BouncyCastle moved from 1.81 to 1.85.2. It is the one flagged dependency that actually
  ships: everything else Snyk reported came from configurations that never reach the APK.
- Netty 4.1.137, Protobuf 3.25.5 and Logback 1.5.37 are enforced across every Gradle
  configuration, including AGP's test harness and ktlint, so build tooling is not left on
  vulnerable transitive releases merely because it is absent from the APK.
- ML-KEM and ML-DSA use BouncyCastle's current low-level APIs instead of their deprecated
  `pqc.crypto` predecessors. Hybrid public/private keys and signatures now reject wrong
  lengths before copying or parsing attacker-controlled data.
- The BLE advert's block encryption no longer goes through
  `Cipher.getInstance("AES/ECB/NoPadding")`. It asks BouncyCastle for the raw block
  cipher, which is what the CTAP hybrid transport actually specifies. ECB is a rule for
  chaining several blocks and there has only ever been one, so the transformation string
  described the operation inaccurately. A test pins the output against the NIST SP
  800-38A AES-256 vector, so the rewrite is provably byte-identical.
- Snyk resolves only the runtime classpaths. Left to itself it walks every Gradle
  configuration, including the Android Gradle Plugin's internal test-platform ones, and
  reports the gRPC, netty, protobuf and logback stack they carry. None of it is on a
  compile or runtime classpath, and it accounted for around 160 advisories about code
  this project never executes.
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
- The Snyk job calls the `snyk-linux` binary directly instead of the `snyk` shell wrapper
  the setup action installs. That wrapper runs `eval snyk-linux $@`, so
  `--configuration-matching='^(releaseRuntimeClasspath|runtimeClasspath)$'` reached bash as
  a subshell and a pipe rather than as a single argument. The step died on a syntax error,
  no SARIF was written, and 177 dependency alerts stayed open on the Security tab against
  versions this repository had already raised.
- The version floor now also covers `protobuf-java-util`, `protobuf-javalite` and
  `protobuf-kotlin`, and skips `netty-tcnative`, which shares the `io.netty` group but is
  versioned on its own 2.x line and would simply fail to resolve at 4.1.
- Settings are written through `AtomicFile`, read and written under one process-wide lock,
  and bounded in size. `load().copy(...)` followed by `save(...)` from two `SecureSettings`
  instances could interleave, and the loser silently restored an old pinned signing key or
  rollback watermark. Every read-modify-write call site goes through `update {}` instead.
- `Authenticator.cleanup` deleted the wrong Keystore alias. Keys are created under the
  credential id, while cleanup asked for its base64url re-encoding, so the private key
  outlived the credential that named it.
- COSE EC2 public keys encode their coordinates as fixed 32-byte big-endian values.
  `BigInteger.toByteArray()` prepends a zero byte when the high bit is set and drops
  leading zeroes otherwise, so a coordinate could reach a relying party 31 or 33 bytes
  long, which is not what the COSE key format allows.
- Argon2id ceilings drop to 128 MiB, 10 passes and 8 lanes, from 1 GiB, 32 and 64. Those
  parameters arrive inside the vault header, and the old ceiling still let a hostile file
  ask an Android process for a gigabyte. Salt and output lengths are bounded as well.
- The vault framing rejects trailing bytes after the signature, and its bounds check
  subtracts instead of adding, so a length read out of the file cannot overflow into a
  value that passes the check.
- `AuthenticationActivity` is no longer exported. The library starts it from its own
  process, so until now any other application could launch the device-credential prompt.
- The biometric callbacks check `continuation.isActive` before resuming. The framework may
  call back more than once, and resuming a continuation that has already completed throws.

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
