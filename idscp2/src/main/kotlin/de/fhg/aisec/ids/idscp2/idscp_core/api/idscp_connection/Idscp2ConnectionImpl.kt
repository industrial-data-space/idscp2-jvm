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

import de.fhg.aisec.ids.idscp2.idscp_core.FastLatch
import de.fhg.aisec.ids.idscp2.idscp_core.error.Idscp2Exception
import de.fhg.aisec.ids.idscp2.idscp_core.error.Idscp2NotConnectedException
import de.fhg.aisec.ids.idscp2.idscp_core.error.Idscp2TimeoutException
import de.fhg.aisec.ids.idscp2.idscp_core.error.Idscp2WouldBlockException
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.FSM
import org.slf4j.LoggerFactory
import java.util.Collections
import java.util.concurrent.locks.ReentrantLock

/**
 * The IDSCP2 Connection class holds connections between connectors
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 * @author Michael Lux (michael.lux@aisec.fraunhofer.de)
 */
class Idscp2ConnectionImpl(
    private val fsm: FSM,
    override val id: String
) : Idscp2Connection {

    private val connectionListeners = Collections.synchronizedSet(HashSet<Idscp2ConnectionListener>())
    private val messageListeners = Collections.synchronizedSet(HashSet<Idscp2MessageListener>())
    private val connectionListenerLatch = FastLatch()
    private var closed = false
    private var closedLock = ReentrantLock(true)

    override fun unlockMessaging() {
        connectionListenerLatch.unlock()
    }

    /**
     * Close the idscp connection
     */
    override fun close() {
        if (LOG.isInfoEnabled) {
            LOG.info("Closing connection {}...", id)
        }

        // we have to unlock connection listeners to avoid deadlocks with onError()
        // which would block the closedLock until connection listeners are available
        // to avoid error loss
        connectionListenerLatch.unlock()

        /*
         * When closing the connection, also the secure channel and its sockets
         * will be closed. This could lead to errors at the socket listener thread, which
         * should not be passed to the user again. Therefore, we have to remember that
         * the connection has been closed and check this at the onError function.
         *
         * Since the success of the closure depends on weather the connection has been started
         * or not, we should synchronize this sequence to avoid race conditions on the error
         * parsing, as well as avoiding error message loss.
         */
        try {
            closedLock.lock()

            when (val res = fsm.closeConnection()) {
                FSM.FsmResultCode.FSM_NOT_STARTED -> {
                    // not closed
                    throw Idscp2Exception("Handshake not started: " + res.value)
                }
                else -> {
                    // closed
                    closed = true
                    if (LOG.isDebugEnabled) {
                        LOG.debug("IDSCP2 connection {} closed", id)
                    }
                }
            }
        } finally {
            closedLock.unlock()
        }
    }

    /**
     * Send data to the peer IDSCP2 connector
     */

    override fun nonBlockingSend(msg: ByteArray) {
        if (LOG.isInfoEnabled) {
            LOG.info("Sending data via connection {}...", id)
        }

        when (val res = fsm.send(msg)) {
            FSM.FsmResultCode.OK -> return
            FSM.FsmResultCode.WOULD_BLOCK -> throw Idscp2WouldBlockException("Idscp2 connection still waiting for ack")
            FSM.FsmResultCode.IO_ERROR, FSM.FsmResultCode.FSM_LOCKED ->
                throw Idscp2Exception("Connection aborted: " + res.value)
            FSM.FsmResultCode.NOT_CONNECTED ->
                throw Idscp2NotConnectedException("Idscp2 connection temporarily not available")
            else -> throw Idscp2Exception("Idscp2 error occurred while sending data: " + res.value)
        }
    }

    override fun blockingSend(msg: ByteArray, timeout: Long, retryInterval: Long) {
        if (LOG.isInfoEnabled) {
            LOG.info("Sending data via connection {}...", id)
        }

        val start = System.currentTimeMillis()

        while (true) {
            val now = System.currentTimeMillis()
            if (now >= start + timeout) {
                throw Idscp2TimeoutException("Idscp2 connection temporarily not available")
            }

            when (val res = fsm.send(msg)) {
                FSM.FsmResultCode.OK -> return
                FSM.FsmResultCode.WOULD_BLOCK -> {
                    // wait and repeat, fsm currently in wait_for_ack state
                    if (retryInterval > 0)
                        Thread.sleep(retryInterval)
                    continue
                }
                FSM.FsmResultCode.IO_ERROR, FSM.FsmResultCode.FSM_LOCKED ->
                    throw Idscp2Exception("Connection aborted: " + res.value)
                FSM.FsmResultCode.NOT_CONNECTED ->
                    throw Idscp2NotConnectedException("Idscp2 connection temporarily not available")
                else -> throw Idscp2Exception("Idscp2 error occurred while sending data: " + res.value)
            }
        }
    }

    override fun repeatRat() {
        if (LOG.isInfoEnabled) {
            LOG.info("Repeat Rat for connection {}...", id)
        }

        // match result
        when (val res = fsm.repeatRat()) {
            FSM.FsmResultCode.OK -> return
            FSM.FsmResultCode.FSM_LOCKED, FSM.FsmResultCode.IO_ERROR ->
                throw Idscp2Exception("Connection aborted: " + res.value)
            FSM.FsmResultCode.RAT_ERROR ->
                throw Idscp2Exception("RAT action failed: " + res.value)
            else -> throw Idscp2Exception("Error occurred: " + res.value)
        }
    }

    override fun onMessage(msg: ByteArray) {
        // When unlock is called, although not synchronized, this will eventually stop blocking.
        connectionListenerLatch.await()
        if (LOG.isDebugEnabled) {
            LOG.debug("Received new IDSCP Message, notifying {} listeners", messageListeners.size)
        }
        messageListeners.forEach { l: Idscp2MessageListener -> l.onMessage(this, msg) }
    }

    override fun onError(t: Throwable) {
        try {
            closedLock.lock()

            // check if connection has been closed, then we do not want to pass errors to the user
            if (!closed) {
                connectionListenerLatch.await()
                connectionListeners.forEach { idscp2ConnectionListener: Idscp2ConnectionListener ->
                    idscp2ConnectionListener.onError(t)
                }
            }
        } finally {
            closedLock.unlock()
        }
    }

    override fun onClose() {
        connectionListenerLatch.await() // we have to ensure to keep track of closures
        if (LOG.isInfoEnabled) {
            LOG.info("Connection with id {} is closing, notify listeners...", id)
        }
        connectionListeners.forEach { l: Idscp2ConnectionListener -> l.onClose() }
    }

    /**
     * Check if the idscp connection is currently established
     *
     * @return Connection established state
     */
    override val isConnected: Boolean
        get() = fsm.isConnected

    override val isClosed: Boolean
        get() = fsm.isFsmLocked

    override val localDynamicAttributeToken: ByteArray
        get() = fsm.localDat

    override fun addConnectionListener(listener: Idscp2ConnectionListener) {
        connectionListeners.add(listener)
    }

    override fun removeConnectionListener(listener: Idscp2ConnectionListener): Boolean {
        return connectionListeners.remove(listener)
    }

    override fun addMessageListener(listener: Idscp2MessageListener) {
        messageListeners.add(listener)
    }

    override fun removeMessageListener(listener: Idscp2MessageListener): Boolean {
        return messageListeners.remove(listener)
    }

    override fun toString(): String {
        return "Idscp2ConnectionImpl($id)"
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(Idscp2ConnectionImpl::class.java)
    }
}
