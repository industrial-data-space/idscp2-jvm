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

import de.fhg.aisec.ids.idscp2.default_drivers.daps.aisec_daps.AisecDapsDriver
import de.fhg.aisec.ids.idscp2.default_drivers.daps.aisec_daps.AisecDapsDriverConfig
import de.fhg.aisec.ids.idscp2.default_drivers.daps.aisec_daps.SecurityProfile
import de.fhg.aisec.ids.idscp2.default_drivers.daps.aisec_daps.SecurityRequirements
import de.fhg.aisec.ids.idscp2.default_drivers.remote_attestation.dummy.RaProverDummy
import de.fhg.aisec.ids.idscp2.default_drivers.remote_attestation.dummy.RaVerifierDummy
import de.fhg.aisec.ids.idscp2.default_drivers.secure_channel.tlsv1_3.NativeTlsConfiguration
import de.fhg.aisec.ids.idscp2.idscp_core.api.configuration.AttestationConfig
import de.fhg.aisec.ids.idscp2.idscp_core.api.configuration.Idscp2Configuration
import java.nio.file.Paths
import java.util.Objects

object RunTLSClient {
    @JvmStatic
    fun main(args: Array<String>) {

        val keyStorePath = Paths.get(
            Objects.requireNonNull(
                RunTLSClient::class.java.classLoader
                    .getResource("ssl/consumer-keystore.p12")
            ).path
        )

        val trustStorePath = Paths.get(
            Objects.requireNonNull(
                RunTLSClient::class.java.classLoader
                    .getResource("ssl/truststore.p12")
            ).path
        )

        val localAttestationConfig = AttestationConfig.Builder()
            .setSupportedRaSuite(arrayOf(RaProverDummy.RA_PROVER_DUMMY_ID))
            .setExpectedRaSuite(arrayOf(RaVerifierDummy.RA_VERIFIER_DUMMY_ID))
            .setRaTimeoutDelay(300 * 1000L) // 300 seconds
            .build()

        // create daps driver
        val securityRequirements = SecurityRequirements.Builder()
            .setRequiredSecurityLevel(SecurityProfile.INVALID)
            .build()

        val dapsDriver = AisecDapsDriver(
            AisecDapsDriverConfig.Builder()
                .setKeyStorePath(keyStorePath)
                .setTrustStorePath(trustStorePath)
                .setDapsUrl("https://daps-dev.aisec.fraunhofer.de")
                .setSecurityRequirements(securityRequirements)
                .build()
        )

        // create idscp2 config
        val settings = Idscp2Configuration.Builder()
            .setAckTimeoutDelay(500) //  500 ms
            .setHandshakeTimeoutDelay(5 * 1000L) // 5 seconds
            .setAttestationConfig(localAttestationConfig)
            .setDapsDriver(dapsDriver)
            .build()

        // create secureChannel config
        val nativeTlsConfiguration = NativeTlsConfiguration.Builder()
            .setKeyStorePath(keyStorePath)
            .setTrustStorePath(trustStorePath)
            .setCertificateAlias("1.0.1")
            .setHost("provider-core")
            .build()

        val initiator = Idscp2ClientInitiator()
        initiator.init(settings, nativeTlsConfiguration)
    }
}
