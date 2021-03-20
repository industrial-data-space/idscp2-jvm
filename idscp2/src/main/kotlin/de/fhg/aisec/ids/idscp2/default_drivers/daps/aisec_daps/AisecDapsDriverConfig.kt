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

import java.nio.file.Path
import java.nio.file.Paths

/**
 * A Configuration class for the DefaultDapsDriver
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class AisecDapsDriverConfig {
    var dapsUrl = "https://daps.aisec.fraunhofer.de"
        private set
    var keyStorePath: Path = Paths.get("DUMMY-FILENAME.p12")
        private set
    var keyStorePassword: CharArray = "password".toCharArray()
        private set
    var keyAlias = "1"
        private set
    var keyPassword: CharArray = "password".toCharArray()
        private set
    var trustStorePath: Path = Paths.get("DUMMY-FILENAME.p12")
        private set
    var trustStorePassword: CharArray = "password".toCharArray()
        private set
    var securityRequirements: SecurityRequirements? = null
        private set
    var dapsTokenRenewalThreshold: Float = DEFAULT_TOKEN_RENEWAL_THRESHOLD

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
            return config
        }
    }

    companion object {
        const val DEFAULT_TOKEN_RENEWAL_THRESHOLD: Float = 0.666F
    }
}
