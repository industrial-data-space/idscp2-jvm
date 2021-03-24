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

import de.fhg.aisec.ids.idscp2.default_drivers.secure_channel.tlsv1_3.client.TLSClient
import de.fhg.aisec.ids.idscp2.default_drivers.secure_channel.tlsv1_3.server.TLSServer
import de.fhg.aisec.ids.idscp2.idscp_core.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_connection.Idscp2Connection
import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_server.ServerConnectionListener
import de.fhg.aisec.ids.idscp2.idscp_core.drivers.SecureChannelDriver
import de.fhg.aisec.ids.idscp2.idscp_core.drivers.SecureServer
import de.fhg.aisec.ids.idscp2.idscp_core.error.Idscp2Exception
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.FSM
import java.util.concurrent.CompletableFuture

/**
 * An implementation of SecureChannelDriver interface on TLSv1.3
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class NativeTLSDriver<CC : Idscp2Connection> : SecureChannelDriver<CC, NativeTlsConfiguration> {
    /**
     * Performs an asynchronous client connect to a TLS server.
     */
    override fun connect(
        connectionFactory: (FSM, String) -> CC,
        configuration: Idscp2Configuration,
        secureChannelConfig: NativeTlsConfiguration
    ): CompletableFuture<CC> {
        val connectionFuture = CompletableFuture<CC>()
        try {
            val tlsClient = TLSClient(connectionFactory, configuration, secureChannelConfig, connectionFuture)
            tlsClient.connect(secureChannelConfig.host, secureChannelConfig.serverPort)
        } catch (e: Exception) {
            connectionFuture.completeExceptionally(Idscp2Exception("Cannot securely connect to TLS server", e))
        }
        return connectionFuture
    }

    /**
     * Creates and starts a new TLS Server instance.
     *
     * @return The SecureServer instance
     * @throws Idscp2Exception If any error occurred during server creation/start
     */
    override fun listen(
        connectionListenerPromise: CompletableFuture<ServerConnectionListener<CC>>,
        secureChannelConfig: NativeTlsConfiguration,
        serverConfiguration: Idscp2Configuration,
        connectionFactory: (FSM, String) -> CC
    ): SecureServer {
        return try {
            TLSServer(connectionListenerPromise, secureChannelConfig, serverConfiguration, connectionFactory)
        } catch (e: Exception) {
            throw Idscp2Exception("Error while trying to to start SecureServer", e)
        }
    }
}
