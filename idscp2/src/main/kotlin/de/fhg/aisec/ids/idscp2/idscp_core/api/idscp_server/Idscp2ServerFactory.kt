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
package de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_server

import de.fhg.aisec.ids.idscp2.idscp_core.api.Idscp2EndpointListener
import de.fhg.aisec.ids.idscp2.idscp_core.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_connection.Idscp2Connection
import de.fhg.aisec.ids.idscp2.idscp_core.drivers.SecureChannelDriver
import de.fhg.aisec.ids.idscp2.idscp_core.error.Idscp2Exception
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.FSM
import org.slf4j.LoggerFactory
import java.util.concurrent.CompletableFuture

/**
 * Idscp2ServerFactory class, provides IDSCP2 API to the User (Idscp2EndpointListener)
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class Idscp2ServerFactory<CC : Idscp2Connection, SecureChannelConfiguration>(
    private val connectionFactory: (FSM, String) -> CC,
    private val endpointListener: Idscp2EndpointListener<CC>,
    private val serverConfiguration: Idscp2Configuration,
    private val secureChannelDriver: SecureChannelDriver<CC, SecureChannelConfiguration>,
    private val secureChannelConfig: SecureChannelConfiguration
) {

    /**
     * User API to create a new IDSCP2 Server that starts a Secure Server that listens to connections
     */
    @Throws(Idscp2Exception::class)
    fun listen(): Idscp2Server<CC> {
        if (LOG.isInfoEnabled) {
            LOG.info("Starting new IDSCP2 server")
        }
        // create a connection listener promise for the Idscp2Server which is responsible for new connections
        val connectionListenerPromise = CompletableFuture<ServerConnectionListener<CC>>()
        val secureServer = secureChannelDriver.listen(
            connectionListenerPromise, secureChannelConfig,
            serverConfiguration, connectionFactory
        )
        val server = Idscp2Server(secureServer, endpointListener)
        connectionListenerPromise.complete(server)
        return server
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(Idscp2ServerFactory::class.java)
    }
}
