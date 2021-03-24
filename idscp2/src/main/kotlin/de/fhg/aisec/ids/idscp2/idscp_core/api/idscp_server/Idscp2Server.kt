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
import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_connection.Idscp2Connection
import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_connection.Idscp2ConnectionAdapter
import de.fhg.aisec.ids.idscp2.idscp_core.drivers.SecureServer
import org.slf4j.LoggerFactory
import java.util.Collections
import java.util.HashSet

/**
 * An IDSCP2 Server that has the control about the underlying secure server and caches all active
 * connections that belong to the secure server
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class Idscp2Server<CC : Idscp2Connection>(
    private val secureServer: SecureServer,
    private val endpointListener: Idscp2EndpointListener<CC>
) : ServerConnectionListener<CC> {
    private val connections = Collections.synchronizedSet(HashSet<CC>())

    /**
     * Terminate the IDSCP2 server, the secure server and close all connections
     */
    fun terminate() {
        if (LOG.isInfoEnabled) {
            LOG.info("Terminating IDSCP2 server {}", this.toString())
        }

        for (connection in connections) {
            connection.close()
            if (LOG.isDebugEnabled) {
                LOG.debug("Idscp connection with id {} has been closed", connection.id)
            }
            connections.remove(connection)
        }
        secureServer.safeStop()
    }

    override fun onConnectionCreated(connection: CC) {
        if (LOG.isTraceEnabled) {
            LOG.trace("Bind connection with id {} to Idscp2Server {}", connection.id, this.toString())
        }

        // register close listener for unregister connection from the server on closure
        connection.addConnectionListener(object : Idscp2ConnectionAdapter() {
            override fun onClose() {
                connections.remove(connection)
            }
        })

        // add connection to server connections
        connections.add(connection)

        // notify user aboout new connection
        endpointListener.onConnection(connection)

        // Listeners have been applied in onConnection() callback above, so we can safely unlock messaging now
        // thi will also ensure that connection closures are not applied before messaging is unlocked
        connection.unlockMessaging()
    }

    /**
     * If the server is running
     */
    val isRunning: Boolean
        get() = secureServer.isRunning

    /**
     * List of all open IDSCP2 connections of this server
     */
    val allConnections: Set<CC>
        get() = Collections.unmodifiableSet(connections)

    companion object {
        private val LOG = LoggerFactory.getLogger(Idscp2Server::class.java)
    }
}
