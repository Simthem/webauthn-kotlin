# Debug builds are shrunk too, because an unminified Compose app is roughly 36 MB of dex
# and that is a miserable thing to sideload repeatedly. What is deliberately *not* done
# here is obfuscation and optimisation: names stay intact so stack traces and the debugger
# remain useful, and only unreachable code is dropped.
-dontobfuscate
-dontoptimize
-keepattributes SourceFile,LineNumberTable,*Annotation*

# The instrumented tests run against this shrunk APK and call a few members the app
# itself never reaches: the coroutine builders that drive them and the public surface of
# the repository and authenticator they exercise. Release builds are unaffected.
-keep class kotlinx.coroutines.BuildersKt { *; }
-keep class kotlinx.coroutines.AwaitKt { *; }
-keep class com.pqvault.app.data.VaultRepository { public *; }
-keep class com.pqvault.app.data.VaultRepository$Companion { public *; }
-keep class com.pqvault.core.webauthn.SoftwareAuthenticator { public *; }
-keep class com.pqvault.core.webauthn.AuthenticatorData { public *; }
-keep class com.pqvault.core.model.PasskeyEntry { public *; }
# The provider tests build the requests the system would send, and read its answers.
-keep class androidx.credentials.provider.BeginGetCredentialRequest { public *; }
-keep class androidx.credentials.provider.BeginGetPublicKeyCredentialOption { public *; }
-keep class androidx.credentials.provider.BeginGetCredentialResponse { public *; }
-keep class androidx.credentials.provider.CallingAppInfo { public *; }
-keep class androidx.credentials.provider.CredentialEntry { public *; }
-keep class androidx.credentials.provider.PublicKeyCredentialEntry { public *; }
-keep class androidx.credentials.provider.AuthenticationAction { public *; }
