package de.fhg.aisec.ids.idscp2.api

import java.security.MessageDigest
import java.security.cert.Certificate

/**
 * Lookup table for encodeHexString()
 */
private val hexLookup = (0..255).map {
    it.toString(radix = 16).padStart(2, '0')
}

/**
 * Encode a byte array to a hex string
 * @return Hexadecimal representation of the given bytes
 */
fun ByteArray.toHexString(delimiter: CharSequence = ""): String {
    return this.joinToString(delimiter) { hexLookup[java.lang.Byte.toUnsignedInt(it)] }
}

val Certificate.sha256Fingerprint
    get() = MessageDigest.getInstance("SHA-256").digest(encoded).toHexString()
