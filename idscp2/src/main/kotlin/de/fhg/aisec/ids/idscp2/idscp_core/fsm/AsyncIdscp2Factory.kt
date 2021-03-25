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
package de.fhg.aisec.ids.idscp2.idscp_core.fsm

import de.fhg.aisec.ids.idscp2.idscp_core.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_connection.Idscp2Connection
import de.fhg.aisec.ids.idscp2.idscp_core.error.Idscp2HandshakeException
import de.fhg.aisec.ids.idscp2.idscp_core.secure_channel.SecureChannel
import org.slf4j.LoggerFactory
import java.util.UUID
import java.util.concurrent.CompletableFuture

/**
 * An object for initiating IDSCP2 connections for a given secure channel.
 * First the FSM is created and the IDSCP2 handshake is started, on success, the connection is created and the
 * connection future is completed.
 *
 * It ensures that no connection is created when the Idscp2Handshake has failed.
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */

object AsyncIdscp2Factory {
    private val LOG = LoggerFactory.getLogger(AsyncIdscp2Factory::class.java)

    fun <CC : Idscp2Connection> initiateIdscp2Connection(
        secureChannel: SecureChannel,
        configuration: Idscp2Configuration,
        connectionFactory: (FSM, String) -> CC,
        connectionFuture: CompletableFuture<CC>
    ): Boolean {

        if (connectionFuture.isCancelled) {
            secureChannel.close()
            return false
        }

        // create the id for the future connection, it is used in the FSM for better logging readability
        val id: String = UUID.randomUUID().toString()

        // create the FSM for the connection
        val fsm = FSM(
            secureChannel,
            configuration.dapsDriver,
            configuration.attestationConfig,
            configuration.ackTimeoutDelay,
            configuration.handshakeTimeoutDelay,
            id,
            connectionFuture.thenApply { it as Idscp2Connection }
        )

        // register FSM to secure channel, pass peer certificate to FSM
        secureChannel.setFsm(fsm)

        CompletableFuture.runAsync {
            try {
                if (LOG.isDebugEnabled) {
                    LOG.debug("Starting IDSCP2 handshake for future connection with id {}", id)
                }
                fsm.startIdscpHandshake()

                /*
                 * Create connection and notify connection future, which is hold by the user (client) or by the
                 * secure server (server)
                 */
                if (LOG.isDebugEnabled) {
                    LOG.debug("Handshake successful. Create new IDSCP2 connection with id {}", id)
                }

                // create the connection, complete the future and register it to the fsm as listener
                val connection: CC = connectionFactory(fsm, id)
                connectionFuture.complete(connection)

                // close the connection if it was cancelled
                if (connectionFuture.isCancelled) {
                    connection.close()
                }
            } catch (e: Idscp2HandshakeException) {
                // idscp2 handshake failed
                connectionFuture.completeExceptionally(e)
            }
        }
        return true
    }
}
