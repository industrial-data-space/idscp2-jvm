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
import de.fhg.aisec.ids.idscp2.default_drivers.remote_attestation.dummy.RaProverDummy2
import de.fhg.aisec.ids.idscp2.default_drivers.remote_attestation.dummy.RaVerifierDummy2
import de.fhg.aisec.ids.idscp2.default_drivers.secure_channel.tlsv1_3.NativeTlsConfiguration
import de.fhg.aisec.ids.idscp2.idscp_core.api.configuration.AttestationConfig
import de.fhg.aisec.ids.idscp2.idscp_core.api.configuration.Idscp2Configuration
import java.nio.file.Paths
import java.util.*

object RunTLSServer {
    @JvmStatic
    fun main(argv: Array<String>) {

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
            .setSupportedRaSuite(arrayOf(RaProverDummy2.RA_PROVER_DUMMY2_ID))
            .setExpectedRaSuite(arrayOf(RaVerifierDummy2.RA_VERIFIER_DUMMY2_ID))
            .setRaTimeoutDelay(300 * 1000L) // 300 seconds
            .build()

        // create daps config
        val securityRequirements = SecurityRequirements.Builder()
            .setRequiredSecurityLevel(SecurityProfile.INVALID)
            .build()

        val dapsDriver = AisecDapsDriver(
            AisecDapsDriverConfig.Builder()
                .setKeyStorePath(keyStorePath)
                .setTrustStorePath(trustStorePath)
                .setDapsUrl("https://daps.aisec.fraunhofer.de")
                .setSecurityRequirements(securityRequirements)
                .build()
        )

        val settings = Idscp2Configuration.Builder()
            .setAttestationConfig(localAttestationConfig)
            .setDapsDriver(dapsDriver)
            .build()

        val nativeTlsConfiguration = NativeTlsConfiguration.Builder()
            .setKeyStorePath(keyStorePath)
            .setTrustStorePath(trustStorePath)
            .setCertificateAlias("1.0.1")
            .build()

        val initiator = Idscp2ServerInitiator()
        initiator.init(settings, nativeTlsConfiguration)
    }
}
