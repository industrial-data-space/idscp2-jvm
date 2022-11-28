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
import de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.demo.DemoRaProver
import de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.demo.DemoRaVerifier
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.NativeTlsConfiguration
import de.fhg.aisec.ids.idscp2.keystores.KeyStoreUtil.loadKeyStore
import java.nio.file.Paths
import java.security.cert.X509Certificate
import java.util.Objects

object RunTLSServer {
    @JvmStatic
    fun main(argv: Array<String>) {
        val keyStorePath = Paths.get(
            Objects.requireNonNull(
                RunTLSServer::class.java.classLoader
                    .getResource("ssl/provider-keystore.p12")
            ).path
        )

        val trustStorePath = Paths.get(
            Objects.requireNonNull(
                RunTLSServer::class.java.classLoader
                    .getResource("ssl/truststore.p12")
            ).path
        )

        val localAttestationConfig = AttestationConfig.Builder()
            .setSupportedRaSuite(arrayOf(DemoRaProver.DEMO_RA_PROVER_ID))
            .setExpectedRaSuite(arrayOf(DemoRaVerifier.DEMO_RA_VERIFIER_ID))
            .setRaTimeoutDelay(300 * 1000L) // 300 seconds
            .build()

        // create daps config
        val securityRequirements = SecurityRequirements.Builder()
            .setRequiredSecurityLevel(SecurityProfile.INVALID)
            .build()

        val password = "password".toCharArray()

        // Load certificates from local KeyStore
        val ks = loadKeyStore(keyStorePath, password)
        val certificates = ks.aliases().asSequence().toList()
            .filter { ks.isKeyEntry(it) }
            .map { ks.getCertificateChain(it)[0] as X509Certificate }

        val dapsDriver = AisecDapsDriver(
            AisecDapsDriverConfig.Builder()
                .setKeyStorePath(keyStorePath)
                .setKeyStorePassword(password)
                .setKeyPassword(password)
                .setKeyAlias("1")
                .setTrustStorePath(trustStorePath)
                .setTrustStorePassword(password)
                .setDapsUrl("https://daps-dev.aisec.fraunhofer.de")
                .setTransportCerts(certificates)
                .setSecurityRequirements(securityRequirements)
                .build()
        )

        val settings = Idscp2Configuration.Builder()
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
            .setHost("consumer-core")
            .build()

        val initiator = Idscp2ServerInitiator()
        initiator.init(settings, nativeTlsConfiguration)
    }
}
