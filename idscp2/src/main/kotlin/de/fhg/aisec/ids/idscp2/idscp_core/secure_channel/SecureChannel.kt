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
package de.fhg.aisec.ids.idscp2.idscp_core.secure_channel

import de.fhg.aisec.ids.idscp2.idscp_core.drivers.SecureChannelEndpoint
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.fsmListeners.ScFsmListener
import org.slf4j.LoggerFactory
import java.security.cert.X509Certificate
import java.util.concurrent.CompletableFuture

/**
 * A secureChannel which is the secure underlying basis of the IDSCP2 protocol,
 * that implements a secureChannelListener
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class SecureChannel(private val endpoint: SecureChannelEndpoint, private val peerCertificate: X509Certificate?) :
    SecureChannelListener {
    private val fsmPromise = CompletableFuture<ScFsmListener>()

    /*
     * close the secure channel forever
     */
    fun close() {
        if (LOG.isTraceEnabled) {
            LOG.trace("Close secure channel")
        }
        endpoint.close()
    }

    /*
     * Send data via the secure channel endpoint to the peer connector
     *
     * return true if the data has been sent successfully, else false
     */
    fun send(msg: ByteArray): Boolean {
        if (LOG.isTraceEnabled) {
            LOG.trace("Send message via secure channel")
        }
        return endpoint.send(msg)
    }

    override fun onMessage(data: ByteArray) {
        if (LOG.isTraceEnabled) {
            LOG.trace("New raw data has been received via the secure channel")
        }
        fsmPromise.thenAccept { fsmListener: ScFsmListener -> fsmListener.onMessage(data) }
    }

    override fun onError(t: Throwable) {
        // Tell fsm an error occurred in secure channel
        if (LOG.isTraceEnabled) {
            LOG.trace("Error occurred in secure channel")
        }
        fsmPromise.thenAccept { fsmListener: ScFsmListener -> fsmListener.onError(t) }
    }

    override fun onClose() {
        // Tell fsm secure channel received EOF
        if (LOG.isTraceEnabled) {
            LOG.trace("Secure channel received EOF")
        }
        fsmPromise.thenAccept { obj: ScFsmListener -> obj.onClose() }
    }

    val isConnected: Boolean
        get() = endpoint.isConnected

    /*
     * set the corresponding finite state machine, pass peer certificate to FSM
     */
    fun setFsm(fsm: ScFsmListener) {
        if (LOG.isTraceEnabled) {
            LOG.trace("Bind FSM to secure channel and pass peer certificate to FSM")
        }
        fsmPromise.complete(fsm)
        if (peerCertificate != null) {
            fsm.setPeerX509Certificate(peerCertificate)
        }
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(SecureChannel::class.java)
    }
}
