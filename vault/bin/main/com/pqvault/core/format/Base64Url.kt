package com.pqvault.core.format

import java.util.Base64

/** Unpadded base64url, the encoding WebAuthn uses throughout. */
object Base64Url {
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()

    fun encode(bytes: ByteArray): String = encoder.encodeToString(bytes)

    fun decode(text: String): ByteArray = decoder.decode(text)
}
