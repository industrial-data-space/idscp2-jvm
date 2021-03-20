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
package de.fhg.aisec.ids.idscp2.tests

import de.fhg.aisec.ids.idscp2.default_drivers.secure_channel.tlsv1_3.NativeTLSDriver
import de.fhg.aisec.ids.idscp2.default_drivers.secure_channel.tlsv1_3.NativeTlsConfiguration
import de.fhg.aisec.ids.idscp2.idscp_core.api.Idscp2EndpointListener
import de.fhg.aisec.ids.idscp2.idscp_core.api.configuration.AttestationConfig
import de.fhg.aisec.ids.idscp2.idscp_core.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_connection.Idscp2Connection
import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_connection.Idscp2ConnectionAdapter
import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_connection.Idscp2ConnectionImpl
import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_server.Idscp2Server
import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_server.Idscp2ServerFactory
import de.fhg.aisec.ids.idscp2.idscp_core.drivers.DapsDriver
import de.fhg.aisec.ids.idscp2.idscp_core.drivers.RatProverDriver
import de.fhg.aisec.ids.idscp2.idscp_core.drivers.RatVerifierDriver
import de.fhg.aisec.ids.idscp2.idscp_core.error.DatException
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.InternalControlMessage
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.fsmListeners.RatProverFsmListener
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.fsmListeners.RatVerifierFsmListener
import de.fhg.aisec.ids.idscp2.idscp_core.rat_registry.RatProverDriverRegistry
import de.fhg.aisec.ids.idscp2.idscp_core.rat_registry.RatVerifierDriverRegistry
import org.awaitility.Awaitility.await
import org.junit.After
import org.junit.Assert
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.nio.file.Paths
import java.security.cert.X509Certificate
import java.util.Objects
import java.util.concurrent.BlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue

/**
 * Testing the complete IDSCP2 protocol, including re-attestations,
 * message exchange, DAT request, driver acceptors and rejectors
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
private const val VALID_DAT: String = "TEST_TOKEN"

class Idscp2Integration {

    private lateinit var idscpServer: Idscp2Server<Idscp2Connection>

    /**
     * Some custom DAPS driver classes to test the general behavior
     */
    class DapsRejector : DapsDriver {
        override val token: ByteArray
            get() = VALID_DAT.toByteArray()

        override fun verifyToken(dat: ByteArray, peerCertificate: X509Certificate?): Long {
            throw DatException("DapsRejector will reject each token")
        }
    }

    class InvalidDaps : DapsDriver {
        override val token: ByteArray
            get() = throw DatException("InvalidDaps cannot issue DAT")

        override fun verifyToken(dat: ByteArray, peerCertificate: X509Certificate?): Long {
            if (dat.contentEquals(VALID_DAT.toByteArray())) {
                return 3600
            } else {
                throw DatException("Dat is not valid")
            }
        }
    }

    class DapsAcceptor(private val delay: Long) : DapsDriver {
        override val token: ByteArray
            get() = VALID_DAT.toByteArray()

        override fun verifyToken(dat: ByteArray, peerCertificate: X509Certificate?): Long {
            if (dat.contentEquals(VALID_DAT.toByteArray())) {
                return delay
            } else {
                throw DatException("Dat is not valid")
            }
        }
    }

    class CustomRatConfig(val delay: Long)

    /**
     * Some custom RAT drivers
     */
    class RatVerifierAcceptor(fsmListener: RatVerifierFsmListener) : RatVerifierDriver<CustomRatConfig>(fsmListener) {
        private val queue: BlockingQueue<ByteArray> = LinkedBlockingQueue()
        private var delay: Long = 0
        override fun delegate(message: ByteArray) {
            queue.add(message)
        }

        override fun run() {
            try {
                queue.take()
                sleep(delay)
            } catch (e: InterruptedException) {
                if (running) {
                    fsmListener.onRatVerifierMessage(InternalControlMessage.RAT_VERIFIER_FAILED)
                }
                return
            }
            fsmListener.onRatVerifierMessage(InternalControlMessage.RAT_VERIFIER_MSG, "".toByteArray())
            fsmListener.onRatVerifierMessage(InternalControlMessage.RAT_VERIFIER_OK)
        }

        override fun setConfig(config: CustomRatConfig) {
            delay = config.delay
        }
    }

    class RatVerifierRejector(fsmListener: RatVerifierFsmListener) : RatVerifierDriver<CustomRatConfig>(fsmListener) {
        private val queue: BlockingQueue<ByteArray> = LinkedBlockingQueue()
        private var delay: Long = 0
        override fun delegate(message: ByteArray) {
            queue.add(message)
        }

        override fun run() {
            try {
                queue.take()
                sleep(delay)
            } catch (e: InterruptedException) {
                if (running) {
                    fsmListener.onRatVerifierMessage(InternalControlMessage.RAT_VERIFIER_FAILED)
                }
                return
            }
            fsmListener.onRatVerifierMessage(InternalControlMessage.RAT_VERIFIER_MSG, "".toByteArray())
            fsmListener.onRatVerifierMessage(InternalControlMessage.RAT_VERIFIER_FAILED)
        }

        override fun setConfig(config: CustomRatConfig) {
            delay = config.delay
        }
    }

    class RatProverAcceptor(fsmListener: RatProverFsmListener) : RatProverDriver<CustomRatConfig>(fsmListener) {
        private val queue: BlockingQueue<ByteArray> = LinkedBlockingQueue()
        private var delay: Long = 0
        override fun delegate(message: ByteArray) {
            queue.add(message)
        }

        override fun run() {
            fsmListener.onRatProverMessage(InternalControlMessage.RAT_PROVER_MSG, "".toByteArray())
            try {
                queue.take()
                sleep(delay)
            } catch (e: InterruptedException) {
                if (running) {
                    fsmListener.onRatProverMessage(InternalControlMessage.RAT_PROVER_FAILED)
                }
                return
            }
            fsmListener.onRatProverMessage(InternalControlMessage.RAT_PROVER_OK)
        }

        override fun setConfig(config: CustomRatConfig) {
            delay = config.delay
        }
    }

    class RatProverRejector(fsmListener: RatProverFsmListener) : RatProverDriver<CustomRatConfig>(fsmListener) {
        private val queue: BlockingQueue<ByteArray> = LinkedBlockingQueue()
        private var delay: Long = 0
        override fun delegate(message: ByteArray) {
            queue.add(message)
        }

        override fun run() {
            fsmListener.onRatProverMessage(InternalControlMessage.RAT_PROVER_MSG, "".toByteArray())
            try {
                queue.take()
                sleep(delay)
            } catch (e: InterruptedException) {
                if (running) {
                    fsmListener.onRatProverMessage(InternalControlMessage.RAT_PROVER_FAILED)
                }
                return
            }
            fsmListener.onRatProverMessage(InternalControlMessage.RAT_PROVER_FAILED)
        }

        override fun setConfig(config: CustomRatConfig) {
            delay = config.delay
        }
    }

    private fun createIdscp2Config(
        dapsDriver: DapsDriver,
        ackDelay: Long,
        handshakeDelay: Long,
        ratDelay: Long,
        proverSuite: Array<String>,
        verifierSuite: Array<String>
    ): Idscp2Configuration {

        val attestationConfig = AttestationConfig.Builder()
            .setRatTimeoutDelay(ratDelay)
            .setExpectedRatSuite(verifierSuite)
            .setSupportedRatSuite(proverSuite)
            .build()

        return Idscp2Configuration.Builder()
            .setAttestationConfig(attestationConfig)
            .setAckTimeoutDelay(ackDelay)
            .setHandshakeTimeoutDelay(handshakeDelay)
            .setDapsDriver(dapsDriver)
            .build()
    }

    private fun createTlsConfig(keystore: String): NativeTlsConfiguration {

        val keyStorePath = Paths.get(
            Objects.requireNonNull(
                Idscp2Integration::class.java.classLoader
                    .getResource("ssl/$keystore")
            ).path
        )
        val trustStorePath = Paths.get(
            Objects.requireNonNull(
                Idscp2Integration::class.java.classLoader
                    .getResource("ssl/truststore.p12")
            ).path
        )

        return NativeTlsConfiguration.Builder()
            .setHost("localhost")
            .setServerPort(5678)
            .setKeyStorePath(keyStorePath)
            .setTrustStorePath(trustStorePath)
            .setServerSocketTimeout(300)
            .build()
    }

    /**
     * Ensure Idscp2Server is terminated and Registries are cleaned after each Test
     */
    @After
    fun cleanupTest() {
        idscpServer.terminate()
        RatProverDriverRegistry.unregisterDriver("NullRat")
        RatVerifierDriverRegistry.unregisterDriver("NullRat")
    }

    /**
     * Test connection failure
     *
     * Expected Result: Idscp2Connection is created after successful TLS handshake but never reach the
     * established state. Instead, the connection will be closed again.
     */
    private fun expectHandshakeFailure(
        clientConfig: Idscp2Configuration,
        serverConfig: Idscp2Configuration,
        clientTlsConfig: NativeTlsConfiguration,
        serverTlsConfig: NativeTlsConfiguration
    ) {

        val closeLatch = CountDownLatch(2)
        var clientConnection: Idscp2Connection? = null
        var serverConnection: Idscp2Connection? = null

        // start server
        val serverFactory = Idscp2ServerFactory(
            ::Idscp2ConnectionImpl,
            object : Idscp2EndpointListener<Idscp2Connection> {
                override fun onConnection(connection: Idscp2Connection) {
                    serverConnection = connection
                    connection.addConnectionListener(object : Idscp2ConnectionAdapter() {
                        override fun onError(t: Throwable) {
                            Assert.fail(t.stackTraceToString())
                        }

                        override fun onClose() {
                            closeLatch.countDown()
                        }
                    })
                }

                override fun onError(t: Throwable) {
                    Assert.fail(t.stackTraceToString())
                }
            },
            serverConfig,
            NativeTLSDriver(),
            serverTlsConfig,
        )
        idscpServer = serverFactory.listen()
        await().until { idscpServer.isRunning }

        // connect
        val secureChannelDriverClient = NativeTLSDriver<Idscp2Connection>()
        val connectionFuture = secureChannelDriverClient.connect(::Idscp2ConnectionImpl, clientConfig, clientTlsConfig)
        connectionFuture.thenAccept { connection: Idscp2Connection ->
            clientConnection = connection
            connection.addConnectionListener(object : Idscp2ConnectionAdapter() {
                override fun onError(t: Throwable) {
                    Assert.fail(t.stackTraceToString())
                }

                override fun onClose() {
                    closeLatch.countDown()
                }
            })
        }.exceptionally {
            Assert.fail(it.stackTraceToString())
            null
        }

        // wait until connections are closed
        closeLatch.await()
        await().until { clientConnection?.isClosed!! && idscpServer.allConnections.isEmpty() && serverConnection?.isClosed!! }
    }

    /**
     * Test successful connection
     */
    private fun expectHandshakeSuccess(
        clientConfig: Idscp2Configuration,
        serverConfig: Idscp2Configuration,
        clientTlsConfig: NativeTlsConfiguration,
        serverTlsConfig: NativeTlsConfiguration,
        reRatOrDat: Boolean
    ) {

        val connectionLatch = CountDownLatch(2)
        val messageLatchServer = CountDownLatch(3)
        val messageLatchClient = CountDownLatch(2)
        var cc: Idscp2Connection? = null

        // start server
        val serverFactory = Idscp2ServerFactory(
            ::Idscp2ConnectionImpl,
            object : Idscp2EndpointListener<Idscp2Connection> {
                override fun onConnection(connection: Idscp2Connection) {
                    // register listeners
                    connection.addConnectionListener(object : Idscp2ConnectionAdapter() {
                        override fun onError(t: Throwable) {
                            Assert.fail(t.stackTraceToString())
                        }

                        override fun onClose() {}
                    })
                    connection.addMessageListener { _: Idscp2Connection, _: ByteArray ->
                        messageLatchServer.countDown()
                    }
                    connection.unlockMessaging()
                    connectionLatch.countDown()
                }

                override fun onError(t: Throwable) {
                    Assert.fail(t.stackTraceToString())
                }
            },
            serverConfig,
            NativeTLSDriver(),
            serverTlsConfig,
        )
        idscpServer = serverFactory.listen()
        await().until { idscpServer.isRunning }

        // connect
        val secureChannelDriverClient = NativeTLSDriver<Idscp2Connection>()
        val connectionFuture = secureChannelDriverClient.connect(::Idscp2ConnectionImpl, clientConfig, clientTlsConfig)
        connectionFuture.thenAccept { connection: Idscp2Connection ->
            connection.addConnectionListener(object : Idscp2ConnectionAdapter() {
                override fun onError(t: Throwable) {
                    Assert.fail(t.stackTraceToString())
                }

                override fun onClose() {}
            })
            connection.addMessageListener { _: Idscp2Connection, _: ByteArray ->
                messageLatchClient.countDown()
            }
            connection.unlockMessaging()
            cc = connection
            connectionLatch.countDown()
        }.exceptionally {
            Assert.fail(it.stackTraceToString())
            null
        }

        // wait for client-side and server-side connection
        connectionLatch.await()

        // get the connection from the server
        assert(idscpServer.allConnections.size == 1)
        val serverConnection = idscpServer.allConnections.first()
        val clientConnection = cc!!

        // wait until connected
        await().until { clientConnection.isConnected && serverConnection.isConnected }

        if (reRatOrDat) {

            // ensure re-attestation takes place
            await().until { !clientConnection.isConnected && !serverConnection.isConnected }

            // wait until re-attestation was successful
            await().until { clientConnection.isConnected && serverConnection.isConnected }
        } else {

            // send two message from the client to the server via blocking send
            clientConnection.blockingSend("ONE".toByteArray(StandardCharsets.UTF_8), 2000, 100)
            clientConnection.blockingSend("TWO".toByteArray(StandardCharsets.UTF_8), 2000, 100)

            // start a remote attestation from the client
            clientConnection.repeatRat()
            assert(!clientConnection.isConnected)

            // wait until repeat RAT is done
            await().until { clientConnection.isConnected && serverConnection.isConnected }

            // send from server to client
            serverConnection.blockingSend("THREE".toByteArray(StandardCharsets.UTF_8), 2000, 100)

            // repeat RAT from server
            serverConnection.repeatRat()
            assert(!serverConnection.isConnected)

            // wait until repeat RAT is done
            await().until { clientConnection.isConnected && serverConnection.isConnected }

            // send one message from client and one from server
            clientConnection.blockingSend("FOUR".toByteArray(StandardCharsets.UTF_8), 2000, 100)
            serverConnection.blockingSend("FIFE".toByteArray(StandardCharsets.UTF_8), 2000, 100)

            // ensure all messages were received
            messageLatchClient.await()
            messageLatchServer.await()
        }

        // close from client
        clientConnection.close()
        await().until { clientConnection.isClosed && serverConnection.isClosed && idscpServer.allConnections.isEmpty() }
    }

    /**
     * Test a complete valid IDSCP2 connection.
     *
     * This includes sending messages from client and server, re-attestations from client and server
     * and closing the connection
     */
    @Test(timeout = 40000)
    fun testIdscp2Valid() {

        // create client config
        val clientIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 100, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val clientTlsConfig = createTlsConfig("consumer-keystore.p12")

        // create server config
        val serverIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 100, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val serverTlsConfig = createTlsConfig("provider-keystore.p12")

        // register RAT drivers in shared Registry
        RatProverDriverRegistry.registerDriver("NullRat", ::RatProverAcceptor, CustomRatConfig(100))
        RatVerifierDriverRegistry.registerDriver("NullRat", ::RatVerifierAcceptor, CustomRatConfig(100))

        expectHandshakeSuccess(clientIdscpConfig, serverIdscpConfig, clientTlsConfig, serverTlsConfig, false)
    }

    /**
     * Test connection failure due to handshake timeout client
     *
     * We add a RAT verifier delay to ensure that the handshake takes much longer than the allowed handshake delay
     */
    @Test(timeout = 20000)
    fun testIdscp2HandshakeTimeoutClient() {

        // create client config
        val clientIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 100, 5, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val clientTlsConfig = createTlsConfig("consumer-keystore.p12")

        // create server config
        val serverIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 100, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val serverTlsConfig = createTlsConfig("provider-keystore.p12")

        RatProverDriverRegistry.registerDriver("NullRat", ::RatProverAcceptor, CustomRatConfig(100))
        RatVerifierDriverRegistry.registerDriver("NullRat", ::RatVerifierAcceptor, CustomRatConfig(100))

        expectHandshakeFailure(clientIdscpConfig, serverIdscpConfig, clientTlsConfig, serverTlsConfig)
    }

    /**
     * Test connection failure due to handshake timeout server
     *
     * We add a RAT verifier delay to ensure that the handshake takes much longer than the allowed handshake delay
     */
    @Test(timeout = 20000)
    fun testIdscp2HandshakeTimeoutServer() {

        // create client config
        val clientIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 100, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val clientTlsConfig = createTlsConfig("consumer-keystore.p12")

        // create server config
        val serverIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 100, 5, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val serverTlsConfig = createTlsConfig("provider-keystore.p12")

        RatProverDriverRegistry.registerDriver("NullRat", ::RatProverAcceptor, CustomRatConfig(100))
        RatVerifierDriverRegistry.registerDriver("NullRat", ::RatVerifierAcceptor, CustomRatConfig(100))

        expectHandshakeFailure(clientIdscpConfig, serverIdscpConfig, clientTlsConfig, serverTlsConfig)
    }

    /**
     * Test successful connection with ACK timeouts on client side
     */
    @Test(timeout = 40000)
    fun testIdscp2AckTimeout() {

        // create client config
        val clientIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 1, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val clientTlsConfig = createTlsConfig("consumer-keystore.p12")

        // create server config
        val serverIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 500, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val serverTlsConfig = createTlsConfig("provider-keystore.p12")

        // register RAT drivers in shared Registry
        RatProverDriverRegistry.registerDriver("NullRat", ::RatProverAcceptor, CustomRatConfig(100))
        RatVerifierDriverRegistry.registerDriver("NullRat", ::RatVerifierAcceptor, CustomRatConfig(100))

        expectHandshakeSuccess(clientIdscpConfig, serverIdscpConfig, clientTlsConfig, serverTlsConfig, false)
    }

    /**
     * Test re-rat triggered by timeout on client side
     */
    @Test(timeout = 30000)
    fun testIdscp2RatTimeoutClient() {

        val ratTimeout: Long = 750
        val ratDriverDelay: Long = 500

        // create client config
        val clientIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 100, 5000, ratTimeout,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val clientTlsConfig = createTlsConfig("consumer-keystore.p12")

        // create server config
        val serverIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 100, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val serverTlsConfig = createTlsConfig("provider-keystore.p12")

        // register RAT drivers in shared Registry
        RatProverDriverRegistry.registerDriver("NullRat", ::RatProverAcceptor, CustomRatConfig(ratDriverDelay))
        RatVerifierDriverRegistry.registerDriver("NullRat", ::RatVerifierAcceptor, CustomRatConfig(ratDriverDelay))

        expectHandshakeSuccess(clientIdscpConfig, serverIdscpConfig, clientTlsConfig, serverTlsConfig, true)
    }

    /**
     * Test re-rat triggered by timeout on server side
     */
    @Test(timeout = 30000)
    fun testIdscp2RatTimeoutServer() {

        val ratTimeout: Long = 750
        val ratDriverDelay: Long = 500

        // create client config
        val clientIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 100, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val clientTlsConfig = createTlsConfig("consumer-keystore.p12")

        // create server config
        val serverIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 100, 5000, ratTimeout,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val serverTlsConfig = createTlsConfig("provider-keystore.p12")

        // register RAT drivers in shared Registry
        RatProverDriverRegistry.registerDriver("NullRat", ::RatProverAcceptor, CustomRatConfig(ratDriverDelay))
        RatVerifierDriverRegistry.registerDriver("NullRat", ::RatVerifierAcceptor, CustomRatConfig(ratDriverDelay))

        expectHandshakeSuccess(clientIdscpConfig, serverIdscpConfig, clientTlsConfig, serverTlsConfig, true)
    }

    /**
     * Test connection failure due to RAT mismatch
     */
    @Test(timeout = 20000)
    fun testIdscp2RatMismatch() {

        // create client config
        val clientIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 100, 5000, 3600000,
            arrayOf("NullRat"), arrayOf("NullRat")
        )
        val clientTlsConfig = createTlsConfig("consumer-keystore.p12")

        // create server config
        val serverIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 100, 5000, 3600000,
            arrayOf("NoNullRat"), arrayOf("NoNullRat")
        )
        val serverTlsConfig = createTlsConfig("provider-keystore.p12")

        // register RAT drivers in shared Registry
        RatProverDriverRegistry.registerDriver("NullRat", ::RatProverAcceptor, null)
        RatVerifierDriverRegistry.registerDriver("NullRat", ::RatVerifierAcceptor, null)

        expectHandshakeFailure(clientIdscpConfig, serverIdscpConfig, clientTlsConfig, serverTlsConfig)
    }

    /**
     * Test connection failure due to empty RAT registry
     */
    @Test(timeout = 30000)
    fun testIdscp2EmptyRatRegistry() {

        // create client config
        val clientIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 100, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val clientTlsConfig = createTlsConfig("consumer-keystore.p12")

        // create server config
        val serverIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 100, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val serverTlsConfig = createTlsConfig("provider-keystore.p12")

        expectHandshakeFailure(clientIdscpConfig, serverIdscpConfig, clientTlsConfig, serverTlsConfig)
    }

    /**
     * Test connection failure due to DAT rejection on client side
     */
    @Test(timeout = 20000)
    fun testIdscp2DapsRejectorClient() {

        // create client config
        val clientIdscpConfig = createIdscp2Config(
            DapsRejector(), 100, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val clientTlsConfig = createTlsConfig("consumer-keystore.p12")

        // create server config
        val serverIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 100, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val serverTlsConfig = createTlsConfig("provider-keystore.p12")

        RatProverDriverRegistry.registerDriver("NullRat", ::RatProverAcceptor, null)
        RatVerifierDriverRegistry.registerDriver("NullRat", ::RatVerifierAcceptor, null)

        expectHandshakeFailure(clientIdscpConfig, serverIdscpConfig, clientTlsConfig, serverTlsConfig)
    }

    /**
     * Test connection failure due to DAT rejection on server side
     */
    @Test(timeout = 20000)
    fun testIdscp2DapsRejectorServer() {
        // create client config
        val clientIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 100, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val clientTlsConfig = createTlsConfig("consumer-keystore.p12")

        // create server config
        val serverIdscpConfig = createIdscp2Config(
            DapsRejector(), 100, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val serverTlsConfig = createTlsConfig("provider-keystore.p12")

        RatProverDriverRegistry.registerDriver("NullRat", ::RatProverAcceptor, null)
        RatVerifierDriverRegistry.registerDriver("NullRat", ::RatVerifierAcceptor, null)

        expectHandshakeFailure(clientIdscpConfig, serverIdscpConfig, clientTlsConfig, serverTlsConfig)
    }

    /**
     * Test connection failure due to DatException in getToken method on client side
     */
    @Test(timeout = 20000)
    fun testIdscp2DapsInvalidTokenClient() {

        // create client config
        val clientIdscpConfig = createIdscp2Config(
            InvalidDaps(), 100, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val clientTlsConfig = createTlsConfig("consumer-keystore.p12")

        // create server config
        val serverIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 100, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val serverTlsConfig = createTlsConfig("provider-keystore.p12")

        RatProverDriverRegistry.registerDriver("NullRat", ::RatProverAcceptor, null)
        RatVerifierDriverRegistry.registerDriver("NullRat", ::RatVerifierAcceptor, null)

        expectHandshakeFailure(clientIdscpConfig, serverIdscpConfig, clientTlsConfig, serverTlsConfig)
    }

    /**
     * Test connection failure due to DatException in getToken method on server side
     */
    @Test(timeout = 20000)
    fun testIdscp2DapsInvalidTokenServer() {

        // create client config
        val clientIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 100, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val clientTlsConfig = createTlsConfig("consumer-keystore.p12")

        // create server config
        val serverIdscpConfig = createIdscp2Config(
            InvalidDaps(), 100, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val serverTlsConfig = createTlsConfig("provider-keystore.p12")

        RatProverDriverRegistry.registerDriver("NullRat", ::RatProverAcceptor, null)
        RatVerifierDriverRegistry.registerDriver("NullRat", ::RatVerifierAcceptor, null)

        expectHandshakeFailure(clientIdscpConfig, serverIdscpConfig, clientTlsConfig, serverTlsConfig)
    }

    /**
     * Test connection success with DAT timeout on client side
     */
    @Test(timeout = 40000)
    fun testIdscp2DapsShortLifetimeClient() {

        // create client config
        val clientIdscpConfig = createIdscp2Config(
            DapsAcceptor(2), 500, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val clientTlsConfig = createTlsConfig("consumer-keystore.p12")

        // create server config
        val serverIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 500, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val serverTlsConfig = createTlsConfig("provider-keystore.p12")

        // register RAT drivers in shared Registry
        RatProverDriverRegistry.registerDriver("NullRat", ::RatProverAcceptor, CustomRatConfig(200))
        RatVerifierDriverRegistry.registerDriver("NullRat", ::RatVerifierAcceptor, CustomRatConfig(200))

        expectHandshakeSuccess(clientIdscpConfig, serverIdscpConfig, clientTlsConfig, serverTlsConfig, false)
    }

    /**
     * Test connection success with DAT timeout on client side
     */
    @Test(timeout = 40000)
    fun testIdscp2DapsShortLifetimeServer() {

        // create client config
        val clientIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 500, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val clientTlsConfig = createTlsConfig("consumer-keystore.p12")

        // create server config
        val serverIdscpConfig = createIdscp2Config(
            DapsAcceptor(2), 500, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val serverTlsConfig = createTlsConfig("provider-keystore.p12")

        // register RAT drivers in shared Registry
        RatProverDriverRegistry.registerDriver("NullRat", ::RatProverAcceptor, CustomRatConfig(200))
        RatVerifierDriverRegistry.registerDriver("NullRat", ::RatVerifierAcceptor, CustomRatConfig(200))

        expectHandshakeSuccess(clientIdscpConfig, serverIdscpConfig, clientTlsConfig, serverTlsConfig, false)
    }

    /**
     * Test connection failure due to RAT verifier failure
     */
    @Test(timeout = 20000)
    fun testIdscp2RatVerifierRejector() {
        // create client config
        val clientIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 500, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val clientTlsConfig = createTlsConfig("consumer-keystore.p12")

        // create server config
        val serverIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 500, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val serverTlsConfig = createTlsConfig("provider-keystore.p12")

        RatProverDriverRegistry.registerDriver("NullRat", ::RatProverAcceptor, null)
        RatVerifierDriverRegistry.registerDriver("NullRat", ::RatVerifierRejector, null)

        expectHandshakeFailure(clientIdscpConfig, serverIdscpConfig, clientTlsConfig, serverTlsConfig)
    }

    /**
     * Test connection failure due to RAT prover failure
     */
    @Test(timeout = 20000)
    fun testIdscp2RatProverRejector() {
        // create client config
        val clientIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 500, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val clientTlsConfig = createTlsConfig("consumer-keystore.p12")

        // create server config
        val serverIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 500, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val serverTlsConfig = createTlsConfig("provider-keystore.p12")

        RatProverDriverRegistry.registerDriver("NullRat", ::RatProverRejector, null)
        RatVerifierDriverRegistry.registerDriver("NullRat", ::RatVerifierAcceptor, null)

        expectHandshakeFailure(clientIdscpConfig, serverIdscpConfig, clientTlsConfig, serverTlsConfig)
    }

    /**
     * Test connection failure due to RAT verifier and prover failure
     */
    @Test(timeout = 20000)
    fun testIdscp2RatRejectors() {
        // create client config
        val clientIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 500, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val clientTlsConfig = createTlsConfig("consumer-keystore.p12")

        // create server config
        val serverIdscpConfig = createIdscp2Config(
            DapsAcceptor(3600), 500, 5000, 3600000,
            arrayOf("NotUsed", "NullRat"), arrayOf("NullRat", "NotUsed")
        )
        val serverTlsConfig = createTlsConfig("provider-keystore.p12")

        RatProverDriverRegistry.registerDriver("NullRat", ::RatProverRejector, null)
        RatVerifierDriverRegistry.registerDriver("NullRat", ::RatVerifierRejector, null)

        expectHandshakeFailure(clientIdscpConfig, serverIdscpConfig, clientTlsConfig, serverTlsConfig)
    }
}
