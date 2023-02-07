/*-
 * ========================LICENSE_START=================================
 * idscp2-examples
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
package de.fhg.aisec.ids.idscp2.example

import de.fhg.aisec.ids.idscp2.api.configuration.AttestationConfig
import de.fhg.aisec.ids.idscp2.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.daps.aisecdaps.AisecDapsDriver
import de.fhg.aisec.ids.idscp2.daps.aisecdaps.AisecDapsDriverConfig
import de.fhg.aisec.ids.idscp2.daps.aisecdaps.SecurityProfile
import de.fhg.aisec.ids.idscp2.daps.aisecdaps.SecurityRequirements
import de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.gramine.GramineRaProver
import de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.gramine.GramineRaVerifier
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.NativeTlsConfiguration
import java.nio.file.Paths
import java.util.Objects

object RunTLSServer {
    @JvmStatic
    fun main(argv: Array<String>) {
        // TODO: Key Store file 'localhost.p12' missing and must be provided!
        val keyStorePath = Paths.get(
            Objects.requireNonNull(
                RunTLSServer::class.java.classLoader
                    .getResource("ssl/localhost.p12")
            ).path
        )

        val trustStorePath = Paths.get(
            Objects.requireNonNull(
                RunTLSServer::class.java.classLoader
                    .getResource("ssl/truststore.p12")
            ).path
        )

        val localAttestationConfig = AttestationConfig.Builder()
            .setSupportedRaSuite(arrayOf(GramineRaProver.GRAMINE_RA_PROVER_ID))
            .setExpectedRaSuite(arrayOf(GramineRaVerifier.GRAMINE_RA_VERIFIER_ID))
            .setRaTimeoutDelay(300 * 1000L) // 300 seconds
            .build()

        val password = "password".toCharArray()

        // create daps config
        val securityRequirements = SecurityRequirements.Builder()
            .setRequiredSecurityLevel(SecurityProfile.INVALID)
            .build()

        val dapsDriver = AisecDapsDriver(
            AisecDapsDriverConfig.Builder()
                .setKeyStorePath(keyStorePath)
                .setKeyStorePassword(password)
                .setKeyPassword(password)
                .setTrustStorePath(trustStorePath)
                .setTrustStorePassword(password)
                .setKeyAlias("1")
                .setDapsUrl("https://daps.aisec.fraunhofer.de")
                .setSecurityRequirements(securityRequirements)
                .build()
        )

        val settings = Idscp2Configuration.Builder()
            .setAckTimeoutDelay(20 * 1000L) //  20 seconds
            .setHandshakeTimeoutDelay(50 * 1000L) // 50 seconds
            .setAttestationConfig(localAttestationConfig)
            .setDapsDriver(dapsDriver)
            .build()

        val nativeTlsConfiguration = NativeTlsConfiguration.Builder()
            .setKeyStorePath(keyStorePath)
            .setKeyStorePassword(password)
            .setKeyPassword(password)
            .setTrustStorePath(trustStorePath)
            .setTrustStorePassword(password)
            .setCertificateAlias("1.0.1")
            .setServerPort(29292)
            .build()

        val initiator = Idscp2ServerInitiator()
        initiator.init(settings, nativeTlsConfiguration)
    }
}
