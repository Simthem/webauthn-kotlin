package com.pqvault.desktop

import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import kotlin.system.exitProcess

/** Started by libpqvault-sk.so for one enrolment or one signature. */
fun main() {
    val prompt = TerminalPrompt.open()
    val response = runCatching {
        val request = HelperProtocol.readRequest(FileInputStream(FileDescriptor.`in`))
        SshAuthenticator(HybridClient(BluezAdverts(), WebSocketTunnels(), prompt), prompt).handle(request)
    }.getOrElse {
        prompt.failed(it.message ?: "invalid request")
        HelperProtocol.Response.Failed(HelperProtocol.ERR_GENERAL)
    }
    FileOutputStream(FileDescriptor.out).use { HelperProtocol.writeResponse(it, response) }
    // OkHttp keeps idle threads alive for a minute, which would hold OpenSSH back.
    exitProcess(0)
}
