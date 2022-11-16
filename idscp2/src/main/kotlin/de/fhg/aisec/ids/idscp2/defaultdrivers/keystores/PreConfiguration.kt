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
package de.fhg.aisec.ids.idscp2.defaultdrivers.keystores

import de.fhg.aisec.ids.idscp2.defaultdrivers.keystores.KeyStoreUtil.loadKeyStore
import java.nio.file.Path
import java.security.Key
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.PKIXBuilderParameters
import java.security.cert.PKIXParameters
import java.security.cert.X509CertSelector
import java.security.cert.X509Certificate
import java.util.Collections
import java.util.Date
import javax.net.ssl.KeyManager
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509ExtendedTrustManager
import kotlin.io.path.absolutePathString

/**
 * A class for creating pre-configured TrustManagers and KeyManagers for TLS Server and TLS Client
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
object PreConfiguration {
    private val TRUST_MANAGERS = Collections.synchronizedMap(mutableMapOf<String, X509ExtendedTrustManager>())

    /*
     * Get a secure X509ExtendedTrustManager for the SslContext
     *
     * throws IllegalStateException if number of available X509TrustManager is not one
     * throws RuntimeException of creating TrustManager fails
     */
    fun getX509ExtTrustManager(
        trustStorePath: Path,
        trustStorePassword: CharArray
    ): X509ExtendedTrustManager {
        // Cache constructed TrustManager instances by TrustStore path
        return TRUST_MANAGERS.computeIfAbsent(trustStorePath.absolutePathString()) {
            val trustManagers = TrustManagerFactory.getInstance("PKIX").apply {
                init(loadKeyStore(trustStorePath, trustStorePassword))
            }.trustManagers
            // Allow only X509 Authentication
            if (trustManagers.size == 1 && trustManagers[0] is X509ExtendedTrustManager) {
                // TODO algorithm constraints (also adapt the caching logic!)
                trustManagers[0] as X509ExtendedTrustManager
            } else {
                throw IllegalStateException("Unexpected default trust manager(s): " + trustManagers.contentToString())
            }
        }
    }

    /*
     * Get a secure X509ExtendedKeyManager for the SslContext
     *
     * throws IllegalStateException if number of available X509KeyManager is not one
     * throws RuntimeException of creating KeyManager fails
     */
    fun getX509ExtKeyManager(
        keyPassword: CharArray,
        keyStorePath: Path,
        keyStorePassword: CharArray,
        certAlias: String,
        keyType: String
    ): Array<KeyManager> {
        val myKeyManager: Array<KeyManager>
        val keystore = loadKeyStore(keyStorePath, keyStorePassword)
        val keyManagerFactory = KeyManagerFactory.getInstance("PKIX") // PKIX from SunJSSE
        keyManagerFactory.init(keystore, keyPassword)
        myKeyManager = keyManagerFactory.keyManagers

        /* set up keyManager config */
        // allow only X509 Authentication
        if (myKeyManager.size == 1 && myKeyManager[0] is X509ExtendedKeyManager) {
            // select certificate alias
            myKeyManager[0] =
                CustomX509ExtendedKeyManager(certAlias, keyType, myKeyManager[0] as X509ExtendedKeyManager)
            return myKeyManager
        } else {
            throw IllegalStateException(
                "Unexpected default key managers:" + myKeyManager.contentToString()
            )
        }
    }

    /**
     * Get a (private) Key from a KeyStore
     */
    fun getKey(
        keyStorePath: Path,
        keyStorePassword: CharArray,
        keyAlias: String,
        keyPassword: CharArray
    ): Key {
        val keyStore = loadKeyStore(keyStorePath, keyStorePassword)
        val key = keyStore.getKey(keyAlias, keyPassword)
        return key ?: throw RuntimeException("No key was found in keystore for given alias")
    }

    /**
     * Get a X509Certificate from a KeyStore, also checking for accessibility of the
     * corresponding (private) Key.
     */
    fun getCertificate(
        keyStorePath: Path,
        keyStorePassword: CharArray,
        keyAlias: String
    ): X509Certificate {
            val keystore = loadKeyStore(keyStorePath, keyStorePassword)
            val cert = keystore.getCertificate(keyAlias) as X509Certificate
            // Probe key alias
            keystore.getKey(keyAlias, keyStorePassword)
            return cert
    }

    /**
     * This method can be used for filtering certificates in a trust store
     * to avoid expired certificates.
     */
    fun filterTrustAnchors(keyStore: KeyStore, validityUntilDate: Date): PKIXBuilderParameters {
        val params = PKIXParameters(keyStore)

        // Create new set of CA certificates that are still valid for specified date
        val validTrustAnchors = params.trustAnchors.filter {
            try {
                it.trustedCert.checkValidity(validityUntilDate)
                true
            } catch (e: CertificateException) {
                false
            }
        }.toSet()

        // Create PKIXBuilderParameters parameters
        return PKIXBuilderParameters(validTrustAnchors, X509CertSelector())
    }
}
