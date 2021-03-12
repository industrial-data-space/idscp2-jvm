package de.fhg.aisec.ids.idscp2.idscp_core.drivers

import java.security.cert.X509Certificate

/**
 * An interface for the DAPS driver, which is used to verify and request dynamicAttributeTokens
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
interface DapsDriver {

    /**
     * Receive a token from the DapsDriver
     */
    val token: ByteArray

    /**
     * Verify a Daps token
     *
     * Return the number of seconds, the DAT is valid
     */
    fun verifyToken(dat: ByteArray): Long

    /**
     * Set the remote peer's certificate to verify DAT attributes that depend on the certificate
     * This will be called from the FSM when the FSM is registered to the secure channel
     */
    fun setPeerX509Certificate(certificate: X509Certificate)
}