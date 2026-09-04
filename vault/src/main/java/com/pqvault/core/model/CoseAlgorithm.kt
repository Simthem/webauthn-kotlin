package com.pqvault.core.model

/**
 * COSE algorithm identifiers, as registered with IANA.
 *
 * The relying party, not us, decides which of these is acceptable, by listing them
 * in `pubKeyCredParams` during registration. That is why ML-DSA cannot simply be made
 * the default: a site that does not list it cannot verify our signature, and the
 * credential would be dead on arrival. We advertise the post-quantum options and fall
 * back to ES256, which every relying party in existence accepts today.
 *
 * ML-DSA identifiers are permanently registered (Recommended status) and specified in
 * draft-ietf-cose-dilithium, so the wire format is settled even though deployment is not.
 */
enum class CoseAlgorithm(val id: Int, val label: String, val postQuantum: Boolean) {
    ES256(-7, "ECDSA P-256 with SHA-256", false),
    EDDSA(-8, "Ed25519", false),
    ML_DSA_44(-48, "ML-DSA-44", true),
    ML_DSA_65(-49, "ML-DSA-65", true),
    ML_DSA_87(-50, "ML-DSA-87", true),
    ;

    companion object {
        fun fromId(id: Int): CoseAlgorithm? = entries.firstOrNull { it.id == id }

        /**
         * Picks the strongest algorithm we support from what the relying party offers,
         * preferring post-quantum when it is on the table. Order within the RP's list is
         * its preference order, but we deliberately override it in favour of PQ: a site
         * that lists ML-DSA at all has opted in to verifying it.
         */
        fun negotiate(relyingPartyPreferences: List<Int>): CoseAlgorithm? {
            val supported = relyingPartyPreferences.mapNotNull { fromId(it) }
            return supported.firstOrNull { it.postQuantum } ?: supported.firstOrNull()
        }
    }
}
