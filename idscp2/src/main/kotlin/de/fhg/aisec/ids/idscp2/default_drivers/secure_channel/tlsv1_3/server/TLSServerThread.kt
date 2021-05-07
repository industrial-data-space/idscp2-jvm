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
package de.fhg.aisec.ids.idscp2.default_drivers.secure_channel.tlsv1_3.server

import de.fhg.aisec.ids.idscp2.default_drivers.secure_channel.tlsv1_3.NativeTlsConfiguration
import de.fhg.aisec.ids.idscp2.default_drivers.secure_channel.tlsv1_3.TLSSessionVerificationHelper
import de.fhg.aisec.ids.idscp2.idscp_core.FastLatch
import de.fhg.aisec.ids.idscp2.idscp_core.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_connection.Idscp2Connection
import de.fhg.aisec.ids.idscp2.idscp_core.drivers.SecureChannelEndpoint
import de.fhg.aisec.ids.idscp2.idscp_core.error.Idscp2Exception
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.AsyncIdscp2Factory
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.FSM
import de.fhg.aisec.ids.idscp2.idscp_core.secure_channel.SecureChannel
import de.fhg.aisec.ids.idscp2.idscp_core.secure_channel.SecureChannelListener
import org.slf4j.LoggerFactory
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.net.SocketTimeoutException
import java.security.cert.X509Certificate
import java.util.concurrent.CompletableFuture
import javax.net.ssl.HandshakeCompletedEvent
import javax.net.ssl.HandshakeCompletedListener
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket

/**
 * A TLSServerThread that notifies an IDSCP2Config when a secure channel was created and the
 * TLS handshake is done
 *
 *
 * When new data are available the serverThread transfers it to the SecureChannelListener
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class TLSServerThread<CC : Idscp2Connection> internal constructor(
    private val sslSocket: SSLSocket,
    private val connectionFuture: CompletableFuture<CC>,
    private val nativeTlsConfiguration: NativeTlsConfiguration,
    private val serverConfiguration: Idscp2Configuration,
    private val connectionFactory: (FSM, String) -> CC
) : Thread(), HandshakeCompletedListener, SecureChannelEndpoint, Closeable {

    @Volatile private var running = true
    private val `in`: DataInputStream
    private val out: DataOutputStream
    private val listenerPromise = CompletableFuture<SecureChannelListener>()
    private val tlsVerificationLatch = FastLatch()

    override fun run() {
        // first run the tls handshake to enforce catching every error occurred during the handshake
        // before reading from buffer
        try {
            sslSocket.startHandshake()

            // Wait for TLS session verification to ensure socket listener is not available before
            // connection is trusted
            tlsVerificationLatch.await()
        } catch (e: Exception) {
            running = false
            connectionFuture.completeExceptionally(
                Idscp2Exception("TLS handshake failed", e)
            )
            return
        }

        // TLS connection established, run socket listener
        var buf: ByteArray
        while (running) {
            try {
                val len = `in`.readInt()
                buf = ByteArray(len)
                `in`.readFully(buf, 0, len)
                onMessage(buf)
            } catch (ignore: SocketTimeoutException) {
                // Timeout catches safeStop() call and allows to send server_goodbye
            } catch (e: EOFException) {
                onClose()
                running = false
            } catch (e: Exception) {
                onError(e)
                running = false
            }
        }
        closeSockets()
    }

    private fun closeSockets() {
        try {
            out.close()
            `in`.close()
            sslSocket.close()
        } catch (ignore: IOException) {}
    }

    override fun send(bytes: ByteArray): Boolean {
        return if (!isConnected) {
            LOG.warn("Server cannot send data because socket is not connected")
            closeSockets()
            false
        } else {
            try {
                out.writeInt(bytes.size)
                out.write(bytes)
                out.flush()
                true
            } catch (e: Exception) {
                LOG.warn("Server could not send data", e)
                false
            }
        }
    }

    private fun onClose() {
        listenerPromise.thenAccept { obj: SecureChannelListener -> obj.onClose() }
    }

    private fun onError(t: Throwable) {
        listenerPromise.thenAccept { obj: SecureChannelListener -> obj.onError(t) }
    }

    fun onMessage(bytes: ByteArray) {
        listenerPromise.thenAccept { listener: SecureChannelListener -> listener.onMessage(bytes) }
    }

    override fun close() {
        safeStop()
    }

    private fun safeStop() {
        running = false
    }

    override val isConnected: Boolean
        get() = sslSocket.isConnected

    override fun handshakeCompleted(handshakeCompletedEvent: HandshakeCompletedEvent) {
        if (LOG.isTraceEnabled) {
            LOG.trace("TLS Handshake was successful")
        }

        try {
            val sslSession = handshakeCompletedEvent.session

            // get peer certificate
            val certificates = sslSession.peerCertificates
            if (certificates.isEmpty()) {
                throw SSLPeerUnverifiedException("Missing peer certificate")
            }
            val peerCert = certificates[0] as X509Certificate

            // verify tls session on application layer: hostname verification, certificate validity
            TLSSessionVerificationHelper.verifyTlsSession(
                sslSession.peerHost, sslSession.peerPort, peerCert,
                nativeTlsConfiguration.hostnameVerificationEnabled,
                false
            )
            if (LOG.isTraceEnabled) {
                LOG.trace("TLS session is valid")
            }

            // provide secure channel to IDSCP2 Config and register secure channel as listener
            val secureChannel = SecureChannel(this, peerCert)
            listenerPromise.complete(secureChannel)

            // initiate idscp2 connection
            AsyncIdscp2Factory.initiateIdscp2Connection(
                secureChannel, serverConfiguration, connectionFactory,
                connectionFuture
            )
        } catch (e: Exception) {
            running = false // set running false before tlsVerificationLatch is decremented, this will cleanup the server thread
            connectionFuture.completeExceptionally(
                Idscp2Exception("TLS session was not valid", e)
            )
        } finally {
            // unblock listener thread
            tlsVerificationLatch.unlock()
        }
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(TLSServerThread::class.java)
    }

    init {
        // Set timeout for blocking read
        sslSocket.soTimeout = nativeTlsConfiguration.socketTimeout
        `in` = DataInputStream(sslSocket.inputStream)
        out = DataOutputStream(sslSocket.outputStream)
    }
}
