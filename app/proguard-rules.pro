# BouncyCastle registers algorithms reflectively through provider tables, so the entry
# points must survive shrinking. Only the packages actually used are kept: bcprov ships
# implementations of dozens of algorithms this app never touches, and letting R8 discard
# them is most of the size win.
-keep class org.bouncycastle.jcajce.provider.** { *; }
-keep class org.bouncycastle.pqc.crypto.mlkem.** { *; }
-keep class org.bouncycastle.pqc.crypto.mldsa.** { *; }
-dontwarn org.bouncycastle.**
-dontwarn javax.naming.**

# kotlinx.serialization generates serializers referenced only by name.
-keepclassmembers class ** {
    *** Companion;
}
-keepclasseswithmembers class ** {
    kotlinx.serialization.KSerializer serializer(...);
}
-keep,includedescriptorclasses class com.pqvault.core.**$$serializer { *; }
-keepclassmembers class com.pqvault.core.** {
    *** Companion;
}

# The credential provider service and the activity behind its PendingIntents are only
# ever instantiated by the system, so nothing in our code references them.
-keep class com.pqvault.app.provider.PqVaultCredentialProviderService { *; }
-keep class com.pqvault.app.provider.CredentialActivity { *; }

# WorkManager instantiates workers by class name.
-keep class com.pqvault.app.sync.VaultSyncWorker { *; }

-dontwarn org.slf4j.**
