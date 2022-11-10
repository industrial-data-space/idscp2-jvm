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
package de.fhg.aisec.ids.idscp2.defaultdrivers.daps.aisecdaps

import de.fhg.aisec.ids.idscp2.core.error.Idscp2Exception
import de.fhg.aisec.ids.idscp2.defaultdrivers.daps.aisecdaps.AisecDapsDriver.Companion.toHexString
import de.fhg.aisec.ids.idscp2.defaultdrivers.keystores.PreConfiguration
import java.nio.file.Path
import java.security.MessageDigest
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManager

/**
 * A Configuration class for the DefaultDapsDriver
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class AisecDapsDriverConfig {
    var dapsUrl = "https://daps.aisec.fraunhofer.de/v3"
        private set
    lateinit var trustStorePath: Path
        private set
    private lateinit var trustStorePassword: CharArray
    private var trustManagerInstance: TrustManager? = null
    lateinit var keyPassword: CharArray
        private set
    lateinit var keyStorePath: Path
        private set
    lateinit var keyStorePassword: CharArray
        private set
    lateinit var keyAlias: String
        private set
    var transportCertsSha256: List<String>? = null
        private set
    var securityRequirements: SecurityRequirements? = null
        private set
    var dapsTokenRenewalThreshold: Float = DEFAULT_TOKEN_RENEWAL_THRESHOLD
    val trustManager by lazy {
        trustManagerInstance ?: PreConfiguration.getX509ExtTrustManager(trustStorePath, trustStorePassword)
    }

    class Builder {
        private val config = AisecDapsDriverConfig()

        fun setDapsUrl(dapsUrl: String): Builder {
            config.dapsUrl = dapsUrl
            return this
        }

        fun setKeyStorePath(path: Path): Builder {
            config.keyStorePath = path
            return this
        }

        fun setKeyStorePassword(password: CharArray): Builder {
            config.keyStorePassword = password
            return this
        }

        fun setKeyAlias(alias: String): Builder {
            config.keyAlias = alias
            return this
        }

        fun setKeyPassword(password: CharArray): Builder {
            config.keyPassword = password
            return this
        }

        fun setTrustStorePath(path: Path): Builder {
            config.trustStorePath = path
            return this
        }

        fun setTrustStorePassword(password: CharArray): Builder {
            config.trustStorePassword = password
            return this
        }

        fun setTrustManager(trustManager: TrustManager): Builder {
            config.trustManagerInstance = trustManager
            return this
        }

        fun setTransportCertsSha256(hashes: List<String>): Builder {
            config.transportCertsSha256 = hashes
            return this
        }

        fun setTransportCerts(certificates: List<X509Certificate>): Builder {
            config.transportCertsSha256 = certificates.map {
                MessageDigest.getInstance("SHA-256").digest(it.encoded).toHexString().lowercase()
            }
            return this
        }

        fun setSecurityRequirements(securityRequirements: SecurityRequirements): Builder {
            config.securityRequirements = securityRequirements
            return this
        }

        fun setTokenRenewalThreshold(threshold: Float): Builder {
            if (0 < threshold && 1 >= threshold) {
                config.dapsTokenRenewalThreshold = threshold
            }
            return this
        }

        fun build(): AisecDapsDriverConfig {
            if (config.trustManagerInstance == null &&
                !(config::trustStorePath.isInitialized && config::trustStorePassword.isInitialized)
            ) {
                throw Idscp2Exception(
                    "Cannot build AisecDapsDriverConfig: Neither trustManager, " +
                        "nor trustStorePath + trustStorePassword have been set!"
                )
            }
            if (!config::keyPassword.isInitialized) {
                throw Idscp2Exception("Cannot build AisecDapsDriverConfig: keyPassword has not been set!")
            }
            if (!config::keyStorePath.isInitialized) {
                throw Idscp2Exception("Cannot build AisecDapsDriverConfig: keyStorePath has not been set!")
            }
            if (!config::keyStorePassword.isInitialized) {
                throw Idscp2Exception("Cannot build AisecDapsDriverConfig: keyStorePassword has not been set!")
            }
            if (!config::keyAlias.isInitialized) {
                throw Idscp2Exception("Cannot build AisecDapsDriverConfig: keyAlias has not been set!")
            }
            return config
        }
    }

    companion object {
        const val DEFAULT_TOKEN_RENEWAL_THRESHOLD: Float = 0.666F
    }
}
