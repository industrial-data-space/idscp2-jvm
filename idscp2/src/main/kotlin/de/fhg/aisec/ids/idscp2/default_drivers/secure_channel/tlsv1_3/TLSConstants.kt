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
package de.fhg.aisec.ids.idscp2.default_drivers.secure_channel.tlsv1_3

/**
 * TLS Constants
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
object TLSConstants {
    // Used TLS version
    const val TLS_INSTANCE = "TLSv1.3"

    // Enabled encryption protocols
    val TLS_ENABLED_PROTOCOLS = arrayOf(TLS_INSTANCE)

    // Acceptable TLS ciphers
    val TLS_ENABLED_CIPHERS = arrayOf(
        // "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        // "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        // "TLS_RSA_WITH_AES_256_GCM_SHA384",
        // "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
        // "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
    )
}
