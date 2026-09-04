package com.pqvault.app.hybrid

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.ParcelUuid
import androidx.core.content.ContextCompat
import com.pqvault.core.hybrid.HybridCrypto
import java.security.SecureRandom
import java.util.UUID

/** Emits the encrypted 20-byte proximity proof expected by a hybrid WebAuthn client. */
class HybridBleAdvertiser(context: Context) {
    private val application = context.applicationContext
    private val adapter = application.getSystemService(BluetoothManager::class.java)?.adapter
    private var callback: AdvertiseCallback? = null

    val permissionGranted: Boolean
        get() = Build.VERSION.SDK_INT < Build.VERSION_CODES.S ||
            ContextCompat.checkSelfPermission(application, Manifest.permission.BLUETOOTH_ADVERTISE) ==
            PackageManager.PERMISSION_GRANTED

    @SuppressLint("MissingPermission")
    fun start(
        secret: ByteArray,
        routingId: ByteArray,
        tunnelDomainId: Int = 0,
        onFailure: (Int) -> Unit = {},
    ): Result<ByteArray> = runCatching {
        check(permissionGranted) { "Bluetooth advertising permission is missing" }
        require(secret.size == 16)
        require(routingId.size == 3)
        require(tunnelDomainId in 0..0xffff)

        val advertiser = adapter?.bluetoothLeAdvertiser
            ?: error("Bluetooth LE advertising is not available on this device")
        stop()

        val plaintext = ByteArray(16)
        plaintext[0] = 0 // QR-initiated tunnel advert.
        SecureRandom().nextBytes(plaintext, 1, 11)
        routingId.copyInto(plaintext, 11)
        plaintext[14] = tunnelDomainId.toByte()
        plaintext[15] = (tunnelDomainId ushr 8).toByte()

        val eidKey = HybridCrypto.derive(secret, purpose = 1, length = 64)
        val ciphertext = HybridCrypto.aesEncryptBlock(eidKey.copyOfRange(0, 32), plaintext)
        val tag = HybridCrypto.hmacSha256(eidKey.copyOfRange(32, 64), ciphertext).copyOf(4)
        val serviceData = ciphertext + tag

        val activeCallback = object : AdvertiseCallback() {
            override fun onStartFailure(errorCode: Int) = onFailure(errorCode)
        }
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(false)
            .setTimeout(0)
            .build()
        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .setIncludeTxPowerLevel(false)
            .addServiceUuid(SERVICE_UUID)
            .addServiceData(SERVICE_UUID, serviceData)
            .build()
        advertiser.startAdvertising(settings, data, activeCallback)
        callback = activeCallback
        plaintext
    }

    @SuppressLint("MissingPermission")
    fun stop() {
        val active = callback ?: return
        if (permissionGranted) adapter?.bluetoothLeAdvertiser?.stopAdvertising(active)
        callback = null
    }

    private fun SecureRandom.nextBytes(output: ByteArray, fromIndex: Int, toIndex: Int) {
        val random = ByteArray(toIndex - fromIndex)
        nextBytes(random)
        random.copyInto(output, fromIndex)
    }

    companion object {
        private val SERVICE_UUID = ParcelUuid(
            UUID.fromString("0000fff9-0000-1000-8000-00805f9b34fb"),
        )
    }
}
