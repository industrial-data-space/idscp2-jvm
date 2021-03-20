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
package de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_connection

import de.fhg.aisec.ids.idscp2.idscp_core.error.Idscp2Exception
import de.fhg.aisec.ids.idscp2.idscp_core.error.Idscp2NotConnectedException
import de.fhg.aisec.ids.idscp2.idscp_core.error.Idscp2TimeoutException
import de.fhg.aisec.ids.idscp2.idscp_core.error.Idscp2WouldBlockException

/**
 * The IDSCP2 Connection class holds connections between connectors
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 * @author Michael Lux (michael.lux@aisec.fraunhofer.de)
 */
interface Idscp2Connection {
    val id: String

    /**
     * Unlock messaging when a message listener is registered, to avoid race conditions
     * and messages loss
     */
    fun unlockMessaging()

    /**
     * Close the idscp connection
     */
    @Throws(Idscp2Exception::class)
    fun close()

    /**
     * Send data to the peer IDSCP2 connector without timeout and retry interval when
     * connection is currently not available
     */
    @Throws(Idscp2Exception::class, Idscp2WouldBlockException::class, Idscp2NotConnectedException::class)
    fun nonBlockingSend(msg: ByteArray)

    /**
     * Send data to the peer IDSCP2 connector and block until done
     */
    @Throws(Idscp2Exception::class, Idscp2TimeoutException::class, Idscp2NotConnectedException::class)
    fun blockingSend(msg: ByteArray, timeout: Long, retryInterval: Long = 0)

    /**
     * Repeat remote attestation verification of remote peer
     */
    @Throws(Idscp2Exception::class)
    fun repeatRat()

    fun onMessage(msg: ByteArray)

    fun onError(t: Throwable)

    fun onClose()

    /**
     * Check if the idscp connection is currently established
     *
     * @return Connection established state
     */
    val isConnected: Boolean

    /**
     * Check if the idscp connection is locked forever
     *
     * @return Connection locked state
     */
    val isClosed: Boolean

    /**
     * Access the local dynamic attribute token
     */
    val localDynamicAttributeToken: ByteArray

    fun addConnectionListener(listener: Idscp2ConnectionListener)

    fun removeConnectionListener(listener: Idscp2ConnectionListener): Boolean

    fun addMessageListener(listener: Idscp2MessageListener)

    fun removeMessageListener(listener: Idscp2MessageListener): Boolean
}
