/*-
 * ========================LICENSE_START=================================
 * idscp2
 * %%
 * Copyright (C) 2021 Fraunhofer AISEC
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =========================LICENSE_END==================================
 */
package de.fhg.aisec.ids.idscp2.default_drivers.daps.aisec_daps

import de.fhg.aisec.ids.idscp2.default_drivers.keystores.PreConfiguration
import de.fhg.aisec.ids.idscp2.idscp_core.drivers.DapsDriver
import de.fhg.aisec.ids.idscp2.idscp_core.error.DatException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier
import org.jose4j.http.Get
import org.jose4j.jwa.AlgorithmConstraints
import org.jose4j.jwk.HttpsJwks
import org.jose4j.jws.AlgorithmIdentifiers
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.NumericDate
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver
import org.json.JSONObject
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets
import java.security.Key
import java.security.KeyManagementException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Date
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509ExtendedTrustManager

/**
 * Default DAPS Driver Implementation for requesting valid dynamicAttributeToken and verifying DAT
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 * @author Gerd Brost (gerd.brost@aisec.fraunhofer.de)
 */
class AisecDapsDriver(config: AisecDapsDriverConfig) : DapsDriver {
    private var sslSocketFactory: SSLSocketFactory
    private var securityRequirements: SecurityRequirements? = config.securityRequirements
    private val trustManager: X509ExtendedTrustManager
    private val privateKey: Key = PreConfiguration.getKey(
        config.keyStorePath,
        config.keyStorePassword,
        config.keyAlias,
        config.keyPassword
    )
    private val dapsUrl: String = config.dapsUrl

    private val localPeerCertificate: X509Certificate =
        PreConfiguration.getCertificate(
            config.keyStorePath,
            config.keyStorePassword,
            config.keyAlias
        )

    /**
     * Lookup table for encodeHexString()
     */
    private val hexLookup = HashMap<Byte, CharArray>()

    // requires hexLookup to be existent
    private val connectorUUID: String = createConnectorUUID(localPeerCertificate)

    /**
     * The token, that will be issued until the renewalTime is over. This mechanism reduces the number
     * of DAPS requests which might be problematic for higher scaling peers.
     * When a connection is requesting a token when the renewalTime is over then the currentToken
     * will be overwritten by a new requested DAT from the DAPS. The new renewalTime is calculated by
     * the renewalThreshold:
     *
     * renewalTime = now + tokenValidityTime (in seconds) * renewalThreshold
     *
     * The threshold must be in (0;1]
     */
    private var currentToken: ByteArray = "INVALID_TOKEN".toByteArray()
    private var renewalTime: NumericDate = NumericDate.now()
    private val renewalThreshold = config.dapsTokenRenewalThreshold
    private val renewalLock = ReentrantLock(true)

    init {
        // create ssl socket factory for secure
        val trustManagers = PreConfiguration.getX509ExtTrustManager(
            config.trustStorePath,
            config.trustStorePassword
        )
        trustManager = trustManagers[0] as X509ExtendedTrustManager
        sslSocketFactory = try {
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, trustManagers, null)
            sslContext.socketFactory
        } catch (e: NoSuchAlgorithmException) {
            LOG.error("Cannot init DefaultDapsDriver: {}", e.toString())
            throw RuntimeException(e)
        } catch (e: KeyManagementException) {
            LOG.error("Cannot init DefaultDapsDriver: {}", e.toString())
            throw RuntimeException(e)
        }
    }

    /**
     * Create connector UUID: SKI:keyid:AKI from X509 Certificate
     */
    private fun createConnectorUUID(certificate: X509Certificate): String {

        // GET 2.5.29.35 AuthorityKeyIdentifier
        val akiOid = Extension.authorityKeyIdentifier.id
        val rawAuthorityKeyIdentifier = certificate.getExtensionValue(akiOid)
        val akiOc = ASN1OctetString.getInstance(rawAuthorityKeyIdentifier)
        val aki = AuthorityKeyIdentifier.getInstance(akiOc.octets)
        val authorityKeyIdentifier = aki.keyIdentifier
        val akiResult = encodeHexString(authorityKeyIdentifier, true).uppercase()

        // GET 2.5.29.14	SubjectKeyIdentifier
        val skiOid = Extension.subjectKeyIdentifier.id
        val rawSubjectKeyIdentifier = certificate.getExtensionValue(skiOid)
        val ski0c = ASN1OctetString.getInstance(rawSubjectKeyIdentifier)
        val ski = SubjectKeyIdentifier.getInstance(ski0c.octets)
        val subjectKeyIdentifier = ski.keyIdentifier
        val skiResult = encodeHexString(subjectKeyIdentifier, true).uppercase()

        if (LOG.isDebugEnabled) {
            LOG.debug("AKI: $akiResult")
            LOG.debug("SKI: $skiResult")
        }

        return skiResult + "keyid:" + akiResult.substring(0, akiResult.length - 1)
    }

    private fun syncGetToken(): ByteArray {
        renewalLock.lock()
        try {
            if (NumericDate.now().isBefore(renewalTime)) {
                // the current token is still valid
                if (LOG.isDebugEnabled) {
                    LOG.debug("Issue cached DAT: {}", currentToken.toString(StandardCharsets.UTF_8))
                }
                return currentToken
            }

            // request a new token from the DAPS
            if (LOG.isInfoEnabled) {
                LOG.info("Retrieving Dynamic Attribute Token from DAPS ...")
            }
            if (LOG.isDebugEnabled) {
                LOG.debug("ConnectorUUID: $connectorUUID")
            }

            // create signed JWT
            val expiration = Date.from(Instant.now().plusSeconds(86400))
            val issuedAt = Date.from(Instant.now())
            val notBefore = Date.from(Instant.now())

            val jwt = Jwts.builder()
                .setIssuer(connectorUUID)
                .setSubject(connectorUUID)
                .claim("@context", "https://w3id.org/idsa/contexts/context.jsonld")
                .claim("@type", "ids:DatRequestToken")
                .setExpiration(expiration)
                .setIssuedAt(issuedAt)
                .setNotBefore(notBefore)
                .setAudience(TARGET_AUDIENCE)
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact()

            // build http client and request for DAPS
            val formBody = FormBody.Builder()
                .add("grant_type", "client_credentials")
                .add(
                    "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                )
                .add("client_assertion", jwt)
                .add("scope", "idsc:IDS_CONNECTOR_ATTRIBUTES_ALL")
                .build()

            val client = OkHttpClient.Builder()
                .sslSocketFactory(sslSocketFactory, trustManager)
                .connectTimeout(15, TimeUnit.SECONDS)
                .writeTimeout(15, TimeUnit.SECONDS)
                .readTimeout(15, TimeUnit.SECONDS)
                .build()

            val request = Request.Builder()
                .url("$dapsUrl/v2/token")
                .post(formBody)
                .build()

            // get http response from DAPS
            val response = client.newCall(request).execute()

            // check for valid response
            if (!response.isSuccessful) {
                LOG.error(
                    "Failed to request token issued with parameters: Issuer: {}, Subject: {}, " +
                        "Expiration: {}, IssuedAt: {}, NotBefore: {}, Audience: {}",
                    connectorUUID,
                    connectorUUID,
                    expiration,
                    issuedAt,
                    notBefore,
                    TARGET_AUDIENCE
                )
                throw DatException("Received non-200 http response: " + response.code)
            }

            if (LOG.isDebugEnabled) {
                LOG.debug("Acquired DAT from {}/v2/token", dapsUrl)
            }
            val json = JSONObject(
                response.body?.string()
                    ?: throw DatException("Received empty DAPS response")
            )

            val token: String
            if (json.has("access_token")) {
                token = json.getString("access_token")
                if (LOG.isDebugEnabled) {
                    LOG.debug("Received DAT from DAPS: {}", token)
                }
            } else if (json.has("error")) {
                throw DatException("DAPS reported error: " + json.getString("error"))
            } else {
                throw DatException("DAPS response does not contain \"access_token\" or \"error\" field.")
            }

            innerVerifyToken(token.toByteArray(StandardCharsets.UTF_8), null, localPeerCertificate, true)
            return token.toByteArray(StandardCharsets.UTF_8)
        } catch (e: Throwable) {
            throw if (e is DatException) {
                e
            } else {
                DatException("Error whilst retrieving DAT", e)
            }
        } finally {
            renewalLock.unlock()
        }
    }

    /**
     * Receive the signed and valid dynamic attribute token from the DAPS
     *
     * @throws DatException
     */
    override val token: ByteArray
        get() = syncGetToken()

    /**
     * Update the security requirements of the DAPS (This might be caused by changes in the connector configuration)
     */
    fun updateSecurityRequirements(securityRequirements: SecurityRequirements?) {
        this.securityRequirements = securityRequirements
    }

    /**
     * Public verifyToken API, used from the IDSCP2 protocol. Security requirements are used from the DAPS config
     * Peer certificate is used for verifying DAT subject
     *
     * @return The number of seconds this DAT is valid
     * @throws DatException
     */
    override fun verifyToken(dat: ByteArray, peerCertificate: X509Certificate?): Long {

        // We expect the peer certificate to validate its fingerprints with the DAT
        if (peerCertificate == null)
            throw DatException("Missing peer certificate for fingerprint validation")

        return innerVerifyToken(dat, securityRequirements, peerCertificate, false)
    }

    /**
     * Verify a given dynamic attribute token, given the security attributes as parameter.
     *
     * If the security requirements is not null and an instance of the SecurityRequirements class
     * the method will also check the provided security attributes of the connector that belongs
     * to the provided DAT
     *
     * The peer certificate is used for validating the fingerprints in the DAT against the peer
     *
     * @return The number of seconds this DAT is valid
     * @throws DatException
     */
    private fun innerVerifyToken(
        dat: ByteArray,
        securityRequirements: SecurityRequirements?,
        certificate: X509Certificate,
        setCurrentToken: Boolean
    ): Long {
        if (LOG.isDebugEnabled) {
            LOG.debug("Verifying dynamic attribute token...")
        }

        // Get JsonWebKey JWK from JsonWebKeyStore JWKS using DAPS JWKS endpoint
        val httpsJwks = HttpsJwks("$dapsUrl/.well-known/jwks.json")
        val getInstance = Get()
        getInstance.setSslSocketFactory(sslSocketFactory)
        httpsJwks.setSimpleHttpGet(getInstance)

        // create new jwks key resolver, selects jwk based on key ID in jwt header
        val jwksKeyResolver = HttpsJwksVerificationKeyResolver(httpsJwks)

        // create validation requirements
        val jwtConsumer = JwtConsumerBuilder()
            .setRequireExpirationTime() // has expiration time
            .setAllowedClockSkewInSeconds(30) // leeway in validation time
            .setRequireSubject() // has subject
            .setExpectedAudience(true, "IDS_Connector", TARGET_AUDIENCE)
            .setExpectedIssuer(dapsUrl) // e.g. https://daps.aisec.fraunhofer.de
            .setVerificationKeyResolver(jwksKeyResolver) // get decryption key from jwks
            .setJweAlgorithmConstraints(
                AlgorithmConstraints(
                    AlgorithmConstraints.ConstraintType.PERMIT,
                    AlgorithmIdentifiers.RSA_USING_SHA256
                )
            )
            .build()

        val validityTime: Long
        val claims: JwtClaims
        try {
            claims = jwtConsumer.processToClaims(String(dat, StandardCharsets.UTF_8))
            val expTime = claims.expirationTime
            validityTime = expTime.value - NumericDate.now().value
        } catch (e: Exception) {
            throw DatException("Error during claims processing", e)
        }

        if (setCurrentToken) {
            // overwrite current local token in daps driver instance
            currentToken = dat
            renewalTime = NumericDate.now()
            renewalTime.addSeconds(validityTime.times(renewalThreshold).toLong())
        }

        // in case of validating remote DAT check the expected fingerprint from the DAT against the peers cert fingerprint
        if (certificate != localPeerCertificate) {
            if (LOG.isDebugEnabled) {
                LOG.debug("Validate peer certificate fingerprint against expected fingerprint from DAT")
            }

            val datCertFingerprints: List<String> = when {
                claims.isClaimValueStringList("transportCertsSha256") -> {
                    claims.getStringListClaimValue("transportCertsSha256")
                }
                claims.isClaimValueString("transportCertsSha256") -> {
                    val fingerprint = claims.getStringClaimValue("transportCertsSha256")
                    listOf(fingerprint)
                }
                else -> {
                    throw DatException("Missing or invalid 'transportCertsSha256' format in DAT")
                }
            }

            // calculate peer certificate SHA256 fingerprint
            val peerCertFingerprint: String
            try {
                val sha256 = MessageDigest.getInstance("SHA-256")
                sha256.update(certificate.encoded)
                val digest = sha256.digest()
                peerCertFingerprint = encodeHexString(digest, false).lowercase()
            } catch (e: Exception) {
                throw DatException("Cannot calculate peer certificate fingerprint", e)
            }

            // check if peer cert fingerprint is a valid fingerprint from the DAT
            if (!datCertFingerprints.contains(peerCertFingerprint)) {
                throw DatException("Fingerprint of peer certificate does not match an expected fingerprint from DAT")
            }
        }

        // check security requirements
        if (securityRequirements != null) {
            if (LOG.isDebugEnabled) {
                LOG.debug("Validate security attributes")
            }
            // parse security profile from DAT
            val securityProfile = claims.getStringClaimValue("securityProfile")
                ?: throw DatException("DAT does not contain securityProfile")
            val securityProfilePeer = SecurityProfile.fromString(securityProfile)
            if (securityProfilePeer < securityRequirements.requiredSecurityLevel) {
                throw DatException(
                    "Peer does not support any valid trust profile: Required: " +
                        securityRequirements.requiredSecurityLevel +
                        " given: " +
                        securityProfilePeer
                )
            }
            if (LOG.isDebugEnabled) {
                LOG.debug("Peer's supported security profile: {}", securityProfilePeer)
            }
        }
        if (LOG.isDebugEnabled) {
            LOG.debug("DAT is valid for {} seconds", validityTime)
        }
        return validityTime
    }

    /**
     * Convert byte to hexadecimal chars without any dependencies to libraries.
     * @param num Byte to get hexadecimal representation for
     * @return The hexadecimal representation of the given byte value
     */
    private fun byteToHex(num: Int): CharArray {
        val hexDigits = CharArray(2)
        hexDigits[0] = Character.forDigit(num shr 4 and 0xF, 16)
        hexDigits[1] = Character.forDigit(num and 0xF, 16)
        return hexDigits
    }

    /**
     * Encode a byte array to a hex string
     * @param byteArray Byte array to get hexadecimal representation for
     * @return Hexadecimal representation of the given bytes
     */
    private fun encodeHexString(byteArray: ByteArray, beautify: Boolean): String {
        val sb = StringBuilder()
        for (b in byteArray) {
            sb.append(hexLookup.computeIfAbsent(b) { num: Byte -> byteToHex(num.toInt()) })
            if (beautify) {
                sb.append(':')
            }
        }
        return sb.toString()
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(AisecDapsDriver::class.java)
        private const val TARGET_AUDIENCE = "idsc:IDS_CONNECTORS_ALL"
    }
}
