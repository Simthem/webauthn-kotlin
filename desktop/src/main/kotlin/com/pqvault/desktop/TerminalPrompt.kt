package com.pqvault.desktop

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.common.BitMatrix
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.io.File
import java.io.FileDescriptor
import java.io.FileOutputStream
import java.io.PrintStream

/** Talks to the user through /dev/tty: standard output belongs to OpenSSH. */
class TerminalPrompt(private val out: PrintStream) : Prompt {

    override fun showCode(code: String, purpose: HybridClient.Purpose) {
        out.println()
        out.println(PromptText.heading(purpose))
        out.println(PromptText.HOW_TO_SCAN)
        out.print(render(matrix(code, margin = 2)))
        out.flush()
    }

    override fun status(stage: HybridClient.Stage) {
        out.println(PromptText.stage(stage))
        out.flush()
    }

    override fun done() {
        out.println("Done.")
        out.flush()
    }

    override fun failed(reason: String) {
        out.println("PQ Vault: $reason.")
        out.flush()
    }

    companion object {
        /** The terminal when there is one, else a window, else standard error. */
        fun open(): Prompt {
            runCatching { PrintStream(FileOutputStream(File("/dev/tty")), true, Charsets.UTF_8) }
                .onSuccess { return TerminalPrompt(it) }
            val stderr = TerminalPrompt(PrintStream(FileOutputStream(FileDescriptor.err), true, Charsets.UTF_8))
            return if (WindowPrompt.available()) WindowPrompt(stderr) else stderr
        }

        fun matrix(text: String, margin: Int): BitMatrix = QRCodeWriter().encode(
            text,
            BarcodeFormat.QR_CODE,
            0,
            0,
            mapOf(EncodeHintType.MARGIN to margin, EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.L),
        )

        /** Two modules per character cell, dark on a forced light background so any theme scans. */
        fun render(matrix: BitMatrix): String {
            val builder = StringBuilder()
            for (y in 0 until matrix.height step 2) {
                builder.append("\u001b[30;47m")
                for (x in 0 until matrix.width) {
                    val top = matrix.get(x, y)
                    val bottom = y + 1 < matrix.height && matrix.get(x, y + 1)
                    builder.append(
                        when {
                            top && bottom -> '█'
                            top -> '▀'
                            bottom -> '▄'
                            else -> ' '
                        },
                    )
                }
                builder.append("\u001b[0m\n")
            }
            return builder.toString()
        }
    }
}
