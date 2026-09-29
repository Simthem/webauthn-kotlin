package com.pqvault.app.diagnostics

import android.content.Context
import android.os.Build
import android.util.AtomicFile
import java.io.File
import java.time.Instant

/** Small, local and deliberately metadata-only journal for field diagnostics. */
class DiagnosticLog(context: Context) {
    private val file = AtomicFile(File(context.filesDir, FILE_NAME))
    private val appContext = context.applicationContext
    private val preferences = appContext.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)

    fun isEnabled(): Boolean = preferences.getBoolean(ENABLED_KEY, true)

    fun setEnabled(enabled: Boolean) {
        preferences.edit().putBoolean(ENABLED_KEY, enabled).apply()
        if (!enabled) clear()
    }

    fun record(event: String, error: Throwable? = null) {
        if (!isEnabled()) return
        // Diagnostics must never be able to break the operation they are observing.
        runCatching {
            synchronized(LOCK) {
                val suffix = error?.let {
                    " | ${it.javaClass.simpleName}: ${sanitize(it.message.orEmpty())}"
                }.orEmpty()
                val line = "${Instant.now()} | ${sanitize(event)}$suffix\n"
                val bytes = (runCatching { file.readFully().toString(Charsets.UTF_8) }
                    .getOrDefault("") + line).toByteArray(Charsets.UTF_8)
                val start = if (bytes.size <= MAX_BYTES) 0 else {
                    var boundary = bytes.size - MAX_BYTES
                    while (boundary < bytes.size && bytes[boundary] != '\n'.code.toByte()) boundary++
                    (boundary + 1).coerceAtMost(bytes.size)
                }
                write(bytes.copyOfRange(start, bytes.size).toString(Charsets.UTF_8))
            }
        }
    }

    fun snapshot(): String = synchronized(LOCK) {
        val version = runCatching {
            val info = appContext.packageManager.getPackageInfo(appContext.packageName, 0)
            "${info.versionName} (${info.longVersionCode})"
        }.getOrDefault("unknown")
        val entries = runCatching { file.readFully().toString(Charsets.UTF_8) }
            .getOrDefault("")
            .ifBlank { "No diagnostic event recorded.\n" }
        buildString {
            appendLine("PQ Vault diagnostics")
            appendLine("App: $version")
            appendLine("Android: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
            appendLine("Device: ${sanitize(Build.MANUFACTURER)} ${sanitize(Build.MODEL)}")
            appendLine("Secrets, credential identifiers and relying-party data are not recorded.")
            appendLine()
            append(entries)
        }
    }

    fun clear() = synchronized(LOCK) { file.delete() }

    private fun write(content: String) {
        val stream = file.startWrite()
        try {
            stream.write(content.toByteArray(Charsets.UTF_8))
            file.finishWrite(stream)
        } catch (error: Throwable) {
            file.failWrite(stream)
            throw error
        }
    }

    companion object {
        private const val FILE_NAME = "diagnostics.log"
        private const val PREFERENCES_NAME = "diagnostics"
        private const val ENABLED_KEY = "enabled"
        private const val MAX_BYTES = 256 * 1024
        private val LOCK = Any()

        /** Defensive last line of protection if a platform exception embeds an URL/token. */
        internal fun sanitize(value: String): String = value
            .replace(Regex("(?i)(wss?|https?)://\\S+"), "<url-redacted>")
            .replace(Regex("(?i)\\b[0-9a-f]{24,}\\b"), "<hex-redacted>")
            .replace(Regex("\\b[A-Za-z0-9_-]{32,}={0,2}\\b"), "<token-redacted>")
            .replace('\n', ' ')
            .replace('\r', ' ')
            .take(500)
    }
}
