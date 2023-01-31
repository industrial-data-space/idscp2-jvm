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

import de.fhg.aisec.ids.idscp2.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.api.connection.Idscp2Connection
import de.fhg.aisec.ids.idscp2.api.connection.Idscp2ConnectionAdapter
import de.fhg.aisec.ids.idscp2.api.raregistry.RaProverDriverRegistry
import de.fhg.aisec.ids.idscp2.api.raregistry.RaVerifierDriverRegistry
import de.fhg.aisec.ids.idscp2.core.connection.Idscp2ConnectionImpl
import de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.demo.DemoRaProver
import de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.demo.DemoRaVerifier
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.NativeTLSDriver
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.NativeTlsConfiguration
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets
import java.util.concurrent.CompletableFuture
import kotlin.concurrent.thread

class CommandlineTunnelClient {
    private lateinit var connectionFuture: CompletableFuture<Idscp2Connection>

    fun init(configuration: Idscp2Configuration, nativeTlsConfiguration: NativeTlsConfiguration) {
        LOG.info("Setting up IDSCP connection")

        // create secure channel driver
        val secureChannelDriver = NativeTLSDriver<Idscp2Connection>()

        // register ra drivers
        RaProverDriverRegistry.registerDriver(
            DemoRaProver.DEMO_RA_PROVER_ID,
            ::DemoRaProver,
            null
        )

        RaVerifierDriverRegistry.registerDriver(
            DemoRaVerifier.DEMO_RA_VERIFIER_ID,
            ::DemoRaVerifier,
            null
        )

        // connect to idscp2 server
        LOG.info("connecting to {}:{}", nativeTlsConfiguration.host, nativeTlsConfiguration.serverPort)
        connectionFuture = secureChannelDriver.connect(::Idscp2ConnectionImpl, configuration, nativeTlsConfiguration)

        connectionFuture.thenAccept { connection: Idscp2Connection ->
            LOG.info("Client: New connection with id " + connection.id)
            var runningUserJob = true

            connection.addConnectionListener(object : Idscp2ConnectionAdapter() {
                override fun onError(t: Throwable) {
                    LOG.error("Client connection error occurred", t)
                    runningUserJob = false
                }

                override fun onClose() {
                    LOG.info("Client: Connection with id " + connection.id + " has been closed")
                    runningUserJob = false
                }
            })

            connection.addMessageListener { _: Idscp2Connection, data: ByteArray ->
                LOG.info("Received message: " + String(data, StandardCharsets.UTF_8))
            }

            connection.unlockMessaging()

            thread {
                // wait until connected
                while (!connection.isConnected) {
                    Thread.sleep(1000L)
                }

                while (runningUserJob) {
                    // read from stdin
                    println("You can now type in your message")
                    val data = readLine()

                    if (data.isNullOrBlank()) {
                        // close connection EOF
                        connection.close()
                    } else {
                        // send data to connection
                        connection.blockingSend(data.toByteArray(StandardCharsets.UTF_8), 2 * 1000L, 100)
                    }
                }
            }
        }.exceptionally { t: Throwable? ->
            LOG.error("Client endpoint error occurred", t)
            null
        }
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(CommandlineTunnelClient::class.java)
    }
}
