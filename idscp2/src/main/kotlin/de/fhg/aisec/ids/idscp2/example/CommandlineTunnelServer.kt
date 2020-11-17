package de.fhg.aisec.ids.idscp2.example

import de.fhg.aisec.ids.idscp2.Idscp2EndpointListener
import de.fhg.aisec.ids.idscp2.drivers.default_driver_impl.daps.NullDaps
import de.fhg.aisec.ids.idscp2.drivers.default_driver_impl.rat.dummy.RatProverDummy
import de.fhg.aisec.ids.idscp2.drivers.default_driver_impl.rat.dummy.RatVerifierDummy
import de.fhg.aisec.ids.idscp2.drivers.default_driver_impl.secure_channel.NativeTLSDriver
import de.fhg.aisec.ids.idscp2.drivers.interfaces.DapsDriver
import de.fhg.aisec.ids.idscp2.idscp_core.Idscp2Connection
import de.fhg.aisec.ids.idscp2.idscp_core.Idscp2ConnectionAdapter
import de.fhg.aisec.ids.idscp2.idscp_core.Idscp2ConnectionImpl
import de.fhg.aisec.ids.idscp2.idscp_core.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.idscp_core.configuration.Idscp2ServerFactory
import de.fhg.aisec.ids.idscp2.idscp_core.rat_registry.RatProverDriverRegistry
import de.fhg.aisec.ids.idscp2.idscp_core.rat_registry.RatVerifierDriverRegistry
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets
import java.util.concurrent.CompletableFuture
import kotlin.concurrent.thread

class CommandlineTunnelServer : Idscp2EndpointListener<Idscp2Connection> {
    fun init(configuration: Idscp2Configuration) {
        LOG.info("setting up IDSCP listener")
        // create secure channel driver
        val secureChannelDriver = NativeTLSDriver<Idscp2Connection>()

        // create daps
        val dapsDriver: DapsDriver = NullDaps()

        // register rat drivers
        RatProverDriverRegistry.registerDriver(
                RatProverDummy.RAT_PROVER_DUMMY_ID, ::RatProverDummy, null)

        RatVerifierDriverRegistry.registerDriver(
                RatVerifierDummy.RAT_VERIFIER_DUMMY_ID, ::RatVerifierDummy, null)

        // create server config
        val serverConfig = Idscp2ServerFactory(
                ::Idscp2ConnectionImpl,
                this,
                configuration,
                dapsDriver,
                secureChannelDriver
        )

        @Suppress("UNUSED_VARIABLE") val idscp2Server = serverConfig.listen()
    }

    override fun onConnection(connection: Idscp2Connection) {
        println("Server: New connection with id " + connection.id)

        connection.addConnectionListener(object : Idscp2ConnectionAdapter() {
            override fun onError(t: Throwable) {
                LOG.error("Server connection error occurred", t)
            }

            override fun onClose() {
                LOG.info("Server: Connection with id " + connection.id + " has been closed")
            }
        })

        connection.addMessageListener { c: Idscp2Connection, data: ByteArray ->
            println("Received message: ${String(data, StandardCharsets.UTF_8)}".trimIndent())
        }

    }

    override fun onError(t: Throwable) {
        LOG.error("Server endpoint error occurred", t)
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(CommandlineTunnelServer::class.java)
    }
}