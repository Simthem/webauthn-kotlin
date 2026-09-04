package com.pqvault.core.webauthn

import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.CborEncoder
import com.pqvault.core.model.CoseAlgorithm
import java.io.ByteArrayOutputStream
import java.security.interfaces.ECPublicKey

/**
 * Encodes a public key as a COSE_Key structure, the form WebAuthn carries inside
 * attested credential data.
 */
object CoseKey {

    private const val KTY = 1L
    private const val ALG = 3L
    private const val CRV = -1L
    private const val X = -2L
    private const val Y = -3L

    private const val KTY_EC2 = 2L
    private const val CRV_P256 = 1L

    /** COSE_Key for an ES256 (P-256) public key: kty=EC2, crv=P-256, with x and y. */
    fun forEs256(publicKey: ECPublicKey): ByteArray {
        val point = publicKey.w
        // Both coordinates are fixed-width 32 bytes; BigInteger.toByteArray may include a
        // leading sign byte or come up short, so each is normalised rather than trusted.
        val x = fixedWidth(point.affineX.toByteArray(), 32)
        val y = fixedWidth(point.affineY.toByteArray(), 32)

        val out = ByteArrayOutputStream()
        CborEncoder(out).encode(
            CborBuilder()
                .addMap()
                .put(KTY, KTY_EC2)
                .put(ALG, CoseAlgorithm.ES256.id.toLong())
                .put(CRV, CRV_P256)
                .put(X, x)
                .put(Y, y)
                .end()
                .build(),
        )
        return out.toByteArray()
    }

    /**
     * COSE_Key for an ML-DSA public key. The key is a single opaque byte string rather
     * than curve coordinates, carried in the same slot the EC coordinates would occupy.
     */
    fun forMlDsa(algorithm: CoseAlgorithm, publicKey: ByteArray): ByteArray {
        require(algorithm.postQuantum) { "${algorithm.label} is not a post-quantum algorithm" }
        val out = ByteArrayOutputStream()
        CborEncoder(out).encode(
            CborBuilder()
                .addMap()
                // kty 7 (AKP, "algorithm key pair") is the type registered for the
                // lattice signature schemes, which have no curve or coordinates.
                .put(KTY, 7L)
                .put(ALG, algorithm.id.toLong())
                .put(CRV, publicKey)
                .end()
                .build(),
        )
        return out.toByteArray()
    }

    internal fun fixedWidth(value: ByteArray, width: Int): ByteArray = when {
        value.size == width -> value
        // Drop the leading zero BigInteger adds to keep a value positive.
        value.size == width + 1 && value[0] == 0.toByte() -> value.copyOfRange(1, value.size)
        value.size < width -> ByteArray(width - value.size) + value
        else -> throw IllegalArgumentException("value is ${value.size} bytes, expected at most $width")
    }
}
