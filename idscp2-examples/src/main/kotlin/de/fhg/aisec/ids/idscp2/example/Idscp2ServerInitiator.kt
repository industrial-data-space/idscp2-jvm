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

import de.fhg.aisec.ids.idscp2.api.Idscp2EndpointListener
import de.fhg.aisec.ids.idscp2.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.api.connection.Idscp2Connection
import de.fhg.aisec.ids.idscp2.api.connection.Idscp2ConnectionAdapter
import de.fhg.aisec.ids.idscp2.api.raregistry.RaProverDriverRegistry
import de.fhg.aisec.ids.idscp2.api.raregistry.RaVerifierDriverRegistry
import de.fhg.aisec.ids.idscp2.api.server.Idscp2ServerFactory
import de.fhg.aisec.ids.idscp2.core.connection.Idscp2ConnectionImpl
import de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.gramine.GramineRaProver
import de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.gramine.GramineRaVerifier
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.NativeTLSDriver
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.NativeTlsConfiguration
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets

class Idscp2ServerInitiator : Idscp2EndpointListener<Idscp2Connection> {
    fun init(configuration: Idscp2Configuration, nativeTlsConfiguration: NativeTlsConfiguration) {
        // create secure channel driver
        val secureChannelDriver = NativeTLSDriver<Idscp2Connection>()

        // register ra drivers
        RaProverDriverRegistry.registerDriver(
            GramineRaProver.GRAMINE_RA_PROVER_ID,
            ::GramineRaProver,
            "Server"
        )

        RaVerifierDriverRegistry.registerDriver(
            GramineRaVerifier.GRAMINE_RA_VERIFIER_ID,
            ::GramineRaVerifier,
            "Server"
        )

        // create server config
        val serverConfig = Idscp2ServerFactory(
            ::Idscp2ConnectionImpl,
            this,
            configuration,
            secureChannelDriver,
            nativeTlsConfiguration
        )

        // run idscp2 server
        @Suppress("UNUSED_VARIABLE")
        val idscp2Server = serverConfig.listen()
    }

    override fun onConnection(connection: Idscp2Connection) {
        LOG.info("Server: New connection with id " + connection.id)
        connection.addConnectionListener(object : Idscp2ConnectionAdapter() {
            override fun onError(t: Throwable) {
                LOG.error("Server connection error occurred", t)
            }

            override fun onClose() {
                LOG.info("Server: Connection with id " + connection.id + " has been closed")
            }
        })
        connection.addMessageListener { c: Idscp2Connection, data: ByteArray ->
            LOG.info("Received ping message: ${String(data, StandardCharsets.UTF_8)}".trimIndent())

            LOG.info("Sending PONG...")
            c.nonBlockingSend("PONG".toByteArray(StandardCharsets.UTF_8))
        }
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(Idscp2ServerInitiator::class.java)
    }
}
