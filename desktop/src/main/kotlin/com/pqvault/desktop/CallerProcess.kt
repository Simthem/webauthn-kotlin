package com.pqvault.desktop

import java.io.File

/**
 * Describes the command that started this request, for the approval screen on the phone.
 * It is what this computer says, and the phone shows it as such.
 */
object CallerProcess {

    private val SKIPPED = setOf("ssh-sk-helper", "pqvault-ssh-helper", "java", "sh")

    /** ssh's options that take a value, from its getopt string. */
    private const val SSH_OPTIONS_WITH_VALUE = "BbcDEeFIiJLlmOoPpQRSWw"

    fun describe(proc: File = File("/proc"), start: Long = ProcessHandle.current().pid()): String? {
        var pid = parent(proc, start) ?: return null
        repeat(MAX_DEPTH) {
            val arguments = arguments(proc, pid) ?: return null
            val program = arguments.firstOrNull()?.substringAfterLast('/') ?: return null
            if (program !in SKIPPED) return summarise(program, arguments.drop(1))
            pid = parent(proc, pid) ?: return null
        }
        return null
    }

    /** The program, and for ssh its destination. Other arguments may hold secrets and stay here. */
    fun summarise(program: String, arguments: List<String>): String {
        if (program != "ssh") return program
        var index = 0
        while (index < arguments.size) {
            val argument = arguments[index]
            if (argument == "--") return listOfNotNull(program, arguments.getOrNull(index + 1)).joinToString(" ")
            if (!argument.startsWith("-") || argument == "-") return "$program $argument"
            val option = argument.getOrNull(1)
            if (option != null && option in SSH_OPTIONS_WITH_VALUE && argument.length == 2) index++
            index++
        }
        return program
    }

    private fun arguments(proc: File, pid: Long): List<String>? = runCatching {
        File(proc, "$pid/cmdline").readBytes().toString(Charsets.UTF_8).split('\u0000').filter(String::isNotEmpty)
    }.getOrNull()?.takeIf(List<String>::isNotEmpty)

    private fun parent(proc: File, pid: Long): Long? = runCatching {
        val stat = File(proc, "$pid/stat").readText()
        stat.substringAfterLast(')').trim().split(' ')[1].toLong()
    }.getOrNull()?.takeIf { it > 1 }

    private const val MAX_DEPTH = 4
}
