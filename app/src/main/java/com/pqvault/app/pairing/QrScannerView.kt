package com.pqvault.app.pairing

import android.content.Context
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Box
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.key
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Camera preview that reports the first QR code it sees.
 *
 * [onScanned] fires at most once: the analyser keeps delivering frames after a hit, and
 * without the latch a single code would be handled several times.
 */
@Composable
fun QrScannerView(
    modifier: Modifier = Modifier,
    resetKey: Any? = null,
    onScanned: (String) -> Unit,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val handled = remember(resetKey) { AtomicBoolean(false) }
    val executor = remember(resetKey) { Executors.newSingleThreadExecutor() }

    DisposableEffect(executor) {
        onDispose {
            executor.shutdownNow()
            val provider = ProcessCameraProvider.getInstance(context)
            if (provider.isDone) runCatching { provider.get().unbindAll() }
        }
    }

    Box(modifier = modifier) {
        key(resetKey) {
            AndroidView(
                modifier = Modifier.matchParentSize(),
                factory = { viewContext ->
                    val previewView = PreviewView(viewContext).apply {
                        scaleType = PreviewView.ScaleType.FILL_CENTER
                    }
                    bindCamera(viewContext, previewView, lifecycleOwner, executor) { text ->
                        if (handled.compareAndSet(false, true)) onScanned(text)
                    }
                    previewView
                },
            )
        }
    }
}

private fun bindCamera(
    context: Context,
    previewView: PreviewView,
    lifecycleOwner: androidx.lifecycle.LifecycleOwner,
    executor: java.util.concurrent.Executor,
    onText: (String) -> Unit,
) {
    val future = ProcessCameraProvider.getInstance(context)
    future.addListener(
        {
            val provider = future.get()
            val preview = Preview.Builder().build().also {
                it.setSurfaceProvider(previewView.surfaceProvider)
            }
            val analysis = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
                .also { it.setAnalyzer(executor) { image -> analyse(image, onText) } }

            runCatching {
                provider.unbindAll()
                provider.bindToLifecycle(
                    lifecycleOwner,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                    analysis,
                )
            }
        },
        ContextCompat.getMainExecutor(context),
    )
}

private fun analyse(image: ImageProxy, onText: (String) -> Unit) {
    try {
        // Plane 0 of YUV_420_888 is the luminance, which is all zxing needs. It is copied
        // row by row because the plane is often padded: rowStride can exceed the image
        // width, and reading the buffer as one block would shear every row and make
        // scanning fail on exactly the devices that pad.
        val plane = image.planes[0]
        val buffer = plane.buffer
        val rowStride = plane.rowStride
        val width = image.width
        val height = image.height

        val luminance = if (rowStride == width) {
            ByteArray(buffer.remaining()).also { buffer.get(it) }
        } else {
            ByteArray(width * height).also { out ->
                val row = ByteArray(rowStride)
                for (y in 0 until height) {
                    val toRead = minOf(rowStride, buffer.remaining())
                    if (toRead <= 0) break
                    buffer.get(row, 0, toRead)
                    System.arraycopy(row, 0, out, y * width, minOf(width, toRead))
                }
            }
        }
        QrCode.decodeLuminance(luminance, width, height)?.let(onText)
    } finally {
        image.close()
    }
}
