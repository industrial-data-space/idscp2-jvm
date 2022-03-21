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

import de.fhg.aisec.ids.idscp2.default_drivers.daps.null_daps.NullDaps
import de.fhg.aisec.ids.idscp2.default_drivers.remote_attestation.demo.DemoRaProver
import de.fhg.aisec.ids.idscp2.default_drivers.remote_attestation.demo.DemoRaVerifier
import de.fhg.aisec.ids.idscp2.default_drivers.secure_channel.tlsv1_3.NativeTlsConfiguration
import de.fhg.aisec.ids.idscp2.idscp_core.api.configuration.AttestationConfig
import de.fhg.aisec.ids.idscp2.idscp_core.api.configuration.Idscp2Configuration
import java.nio.file.Paths
import java.util.Objects

object RunTunnelClient {
    @JvmStatic
    fun main(args: Array<String>) {

        val localAttestationConfig = AttestationConfig.Builder()
            .setSupportedRaSuite(arrayOf(DemoRaProver.DEMO_RA_PROVER_ID))
            .setExpectedRaSuite(arrayOf(DemoRaVerifier.DEMO_RA_VERIFIER_ID))
            .setRaTimeoutDelay(70 * 1000L) // 70 seconds
            .build()

        // create daps driver
        val dapsDriver = NullDaps()

        val config = Idscp2Configuration.Builder()
            .setAckTimeoutDelay(500) //  500 ms
            .setHandshakeTimeoutDelay(5 * 1000L) // 5 seconds
            .setAttestationConfig(localAttestationConfig)
            .setDapsDriver(dapsDriver)
            .build()

        val nativeTlsConfiguration = NativeTlsConfiguration.Builder()
            .setKeyStorePath(Paths.get(Objects.requireNonNull(RunTLSClient::class.java.classLoader.getResource("ssl/consumer-keystore-localhost.p12")).path))
            .setTrustStorePath(Paths.get(Objects.requireNonNull(RunTLSClient::class.java.classLoader.getResource("ssl/truststore.p12")).path))
            .setCertificateAlias("1.0.1")
            .setServerPort(12345)
            .setHost("localhost")
            .build()

        val initiator = CommandlineTunnelClient()
        initiator.init(config, nativeTlsConfiguration)
    }
}
