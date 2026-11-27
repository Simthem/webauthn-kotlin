package com.pqvault.desktop

import com.google.zxing.common.BitMatrix
import java.awt.BorderLayout
import java.awt.Color
import java.awt.GraphicsEnvironment
import java.awt.GridLayout
import java.awt.image.BufferedImage
import javax.swing.BorderFactory
import javax.swing.ImageIcon
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.SwingConstants
import javax.swing.SwingUtilities

/** The same prompt in a small window, for OpenSSH run without a terminal (ssh-agent, Git tools). */
class WindowPrompt(private val fallback: Prompt) : Prompt {
    private var frame: JFrame? = null
    private var status: JLabel? = null
    private var useFallback = false

    override fun showCode(code: String, purpose: HybridClient.Purpose) {
        try {
            SwingUtilities.invokeAndWait {
                val stage = JLabel(" ", SwingConstants.CENTER)
                val header = JPanel(GridLayout(2, 1)).apply {
                    add(JLabel(PromptText.heading(purpose), SwingConstants.CENTER))
                    add(JLabel(PromptText.HOW_TO_SCAN, SwingConstants.CENTER))
                }
                frame = JFrame(PromptText.TITLE).apply {
                    defaultCloseOperation = JFrame.DISPOSE_ON_CLOSE
                    isAlwaysOnTop = true
                    contentPane = JPanel(BorderLayout(0, 12)).apply {
                        border = BorderFactory.createEmptyBorder(16, 16, 16, 16)
                        add(header, BorderLayout.NORTH)
                        add(JLabel(ImageIcon(image(TerminalPrompt.matrix(code, margin = 4), MODULE_PIXELS))), BorderLayout.CENTER)
                        add(stage, BorderLayout.SOUTH)
                    }
                    pack()
                    setLocationRelativeTo(null)
                    isVisible = true
                }
                status = stage
            }
        } catch (_: Throwable) {
            useFallback = true
            fallback.showCode(code, purpose)
        }
    }

    override fun status(stage: HybridClient.Stage) {
        if (useFallback) fallback.status(stage) else onUi { status?.text = PromptText.stage(stage) }
    }

    override fun done() {
        if (useFallback) fallback.done() else onUi { frame?.dispose() }
    }

    override fun failed(reason: String) {
        if (useFallback || frame == null) {
            fallback.failed(reason)
            return
        }
        onUi { status?.text = "PQ Vault: $reason." }
        Thread.sleep(FAILURE_DISPLAY_MILLIS)
        onUi { frame?.dispose() }
    }

    private fun onUi(block: () -> Unit) = runCatching { SwingUtilities.invokeAndWait(block) }

    companion object {
        private const val MODULE_PIXELS = 6
        private const val FAILURE_DISPLAY_MILLIS = 5_000L

        fun available(): Boolean = !GraphicsEnvironment.isHeadless()

        /** Dark modules on white, as every QR scanner expects. */
        fun image(matrix: BitMatrix, scale: Int): BufferedImage {
            val image = BufferedImage(matrix.width * scale, matrix.height * scale, BufferedImage.TYPE_INT_RGB)
            for (y in 0 until image.height) {
                for (x in 0 until image.width) {
                    image.setRGB(x, y, if (matrix.get(x / scale, y / scale)) Color.BLACK.rgb else Color.WHITE.rgb)
                }
            }
            return image
        }
    }
}
