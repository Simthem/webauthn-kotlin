package com.pqvault.app.pairing

import android.graphics.Bitmap
import android.graphics.Color
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.WriterException
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/** QR encoding and decoding, both on top of zxing's pure-Java core. */
object QrCode {

    /**
     * Renders [content] as a QR bitmap, or null when it will not fit in one.
     *
     * Nullable rather than throwing because "too big" is a real, reachable outcome and
     * not an exceptional one: a QR code tops out at 2953 bytes and a payload assembled
     * from user-supplied server details can cross that. It used to propagate out of a
     * composable's remember block, which took the screen down instead of saying so.
     */
    fun encode(content: String, sizePx: Int): Bitmap? {
        val matrix = try {
            QRCodeWriter().encode(
                content,
                BarcodeFormat.QR_CODE,
                sizePx,
                sizePx,
                mapOf(
                    // A pairing payload is long, so medium correction keeps the modules
                    // big enough to scan while leaving room for the data.
                    EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
                    EncodeHintType.MARGIN to 1,
                ),
            )
        } catch (e: WriterException) {
            return null
        } catch (e: IllegalArgumentException) {
            return null
        }
        val pixels = IntArray(matrix.width * matrix.height)
        for (y in 0 until matrix.height) {
            val row = y * matrix.width
            for (x in 0 until matrix.width) {
                pixels[row + x] = if (matrix[x, y]) Color.BLACK else Color.WHITE
            }
        }
        // One bulk write rather than setPixel per module: a 720px code is half a million
        // calls, and on a mid-range phone that is a visible stall before the sheet draws.
        return Bitmap.createBitmap(pixels, matrix.width, matrix.height, Bitmap.Config.RGB_565)
    }

    private val reader = MultiFormatReader().apply {
        setHints(
            mapOf(
                DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
                DecodeHintType.TRY_HARDER to true,
            ),
        )
    }

    /**
     * Decodes a camera frame. Takes the raw luminance plane rather than a Bitmap so we
     * never allocate one per frame: this runs on every frame the analyser delivers.
     */
    @Synchronized
    fun decodeLuminance(data: ByteArray, width: Int, height: Int): String? = try {
        val source = PlanarYUVLuminanceSource(data, width, height, 0, 0, width, height, false)
        reader.decodeWithState(BinaryBitmap(HybridBinarizer(source)))?.text
    } catch (e: Exception) {
        // Not finding a code in a frame is the normal case, not an error worth logging.
        null
    } finally {
        reader.reset()
    }
}
