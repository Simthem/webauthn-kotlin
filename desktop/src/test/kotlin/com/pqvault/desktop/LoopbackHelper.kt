package com.pqvault.desktop

import com.pqvault.core.model.PasskeyEntry
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.io.File
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import kotlin.system.exitProcess

/** Test stand-in for the helper, facing [PhoneSimulator], used by interop/openssh.sh. */
fun main() {
    val dir = File(requireNotNull(System.getenv("PQVAULT_LOOPBACK_DIR")) { "PQVAULT_LOOPBACK_DIR is not set" })
    val mode = File(dir, "mode").readLines()
    val phone = PhoneSimulator(
        verificationAvailable = "uv=available" in mode,
        approves = "user=verify" in mode,
        forgeUnverified = "forge=yes" in mode,
    )
    val serializer = ListSerializer(PasskeyEntry.serializer())
    val state = File(dir, "vault.json")
    if (state.exists()) phone.vault += Json.decodeFromString(serializer, state.readText())

    val request = HelperProtocol.readRequest(FileInputStream(FileDescriptor.`in`))
    val response = SshAuthenticator(HybridClient(phone, phone, phone, timeoutMillis = 30_000), phone).handle(request)
    state.writeText(Json.encodeToString(serializer, phone.vault))
    File(dir, "helper.log").appendText(
        "op=${request.operation} application=${request.application} flags=${request.flags} " +
            "response=${response::class.simpleName} failures=${phone.failures}\n",
    )
    FileOutputStream(FileDescriptor.out).use { HelperProtocol.writeResponse(it, response) }
    exitProcess(0)
}
