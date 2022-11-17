/*-
 * ========================LICENSE_START=================================
 * camel-idscp2
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
@file:Suppress("DEPRECATION")

package de.fhg.aisec.ids.camel.idscp2.client

import de.fhg.aisec.ids.camel.idscp2.ListenerManager
import de.fhg.aisec.ids.camel.idscp2.RefCountingHashMap
import de.fhg.aisec.ids.camel.idscp2.Utils
import de.fhg.aisec.ids.idscp2.applayer.AppLayerConnection
import de.fhg.aisec.ids.idscp2.core.api.configuration.AttestationConfig
import de.fhg.aisec.ids.idscp2.core.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.core.drivers.SecureChannelDriver
import de.fhg.aisec.ids.idscp2.defaultdrivers.daps.aisecdaps.AisecDapsDriver
import de.fhg.aisec.ids.idscp2.defaultdrivers.daps.aisecdaps.AisecDapsDriverConfig
import de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.dummy.RaProverDummy
import de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.dummy.RaProverDummy2
import de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.dummy.RaVerifierDummy
import de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.dummy.RaVerifierDummy2
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.NativeTLSDriver
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.NativeTlsConfiguration
import org.apache.camel.Processor
import org.apache.camel.Producer
import org.apache.camel.spi.UriEndpoint
import org.apache.camel.spi.UriParam
import org.apache.camel.support.DefaultEndpoint
import org.apache.camel.support.jsse.SSLContextParameters
import org.slf4j.LoggerFactory
import java.nio.file.Paths
import java.util.concurrent.CompletableFuture
import java.util.regex.Pattern

@UriEndpoint(
    scheme = "idscp2client",
    title = "IDSCP2 Client Socket",
    syntax = "idscp2client://host:port",
    label = "ids"
)
class Idscp2ClientEndpoint(uri: String?, private val remaining: String, component: Idscp2ClientComponent?) :
    DefaultEndpoint(uri, component) {
    private lateinit var secureChannelDriver: SecureChannelDriver<AppLayerConnection, NativeTlsConfiguration>
    private lateinit var clientConfiguration: Idscp2Configuration
    private lateinit var secureChannelConfig: NativeTlsConfiguration

    @UriParam(
        label = "security",
        description = "The transport encryption SSL context for the IDSCP2 endpoint"
    )
    var transportSslContextParameters: SSLContextParameters? = null

    @UriParam(
        label = "security",
        description = "The DAPS authentication SSL context for the IDSCP2 endpoint"
    )
    var dapsSslContextParameters: SSLContextParameters? = null

    @UriParam(
        label = "security",
        description = "The SSL context for the IDSCP2 endpoint (deprecated)"
    )
    @Deprecated("Depreacted in favor of transportSslContextParameters and dapsSslContextParameters")
    var sslContextParameters: SSLContextParameters? = null

    @UriParam(
        label = "security",
        description = "The validity time of remote attestation and DAT in milliseconds",
        defaultValue = "600000"
    )
    var dapsRaTimeoutDelay: Long? = null

    @UriParam(
        label = "client",
        description = "Used to make N endpoints share the same connection, " +
            "e.g. for using a consumer to receive responses to the requests of another producer"
    )
    var connectionShareId: String? = null

    @UriParam(
        label = "client,producer",
        description = "Makes the client producer block and wait for a reply message from the server"
    )
    var awaitResponse: Boolean = false

    @UriParam(
        label = "common",
        description = "Enable IdsMessage headers (Required for Usage Control)",
        defaultValue = "false"
    )
    var useIdsMessages: Boolean = false

    @UriParam(
        label = "common",
        description = "Locally supported Remote Attestation Suite IDs, separated by \"|\"",
        defaultValue = "${RaProverDummy2.RA_PROVER_DUMMY2_ID}|${RaProverDummy.RA_PROVER_DUMMY_ID}"
    )
    var supportedRaSuites: String = "${RaProverDummy2.RA_PROVER_DUMMY2_ID}|${RaProverDummy.RA_PROVER_DUMMY_ID}"

    @UriParam(
        label = "common",
        description = "Expected Remote Attestation Suite IDs, separated by \"|\", " +
            "each communication peer must support at least one",
        defaultValue = "${RaVerifierDummy2.RA_VERIFIER_DUMMY2_ID}|${RaVerifierDummy.RA_VERIFIER_DUMMY_ID}"
    )
    var expectedRaSuites: String = "${RaVerifierDummy2.RA_VERIFIER_DUMMY2_ID}|${RaVerifierDummy.RA_VERIFIER_DUMMY_ID}"

    @UriParam(
        label = "common",
        description = "Regex for Camel Headers to transfer/copy to/from IDSCP2 via \"extraHeaders\"",
        defaultValue = ""
    )
    var copyHeadersRegex: String? = null

    @UriParam(
        label = "client",
        description = "Max attempts to connect to the IDSCP2 server",
        defaultValue = "3"
    )
    var maxRetries: Long = 3

    @UriParam(
        label = "client",
        description = "Delay after an failed connection attempt to the server, in milliseconds",
        defaultValue = "5000"
    )
    var retryDelayMs: Long = 5000

    @UriParam(
        label = "client",
        description = "Timeout when waiting for a response, in milliseconds",
        defaultValue = "5000"
    )
    var responseTimeout: Long = 5000

    val copyHeadersRegexObject: Regex? by lazy {
        copyHeadersRegex?.let { Regex(it) }
    }

    private fun makeConnectionInternal(): CompletableFuture<AppLayerConnection> {
        return secureChannelDriver.connect(::AppLayerConnection, clientConfiguration, secureChannelConfig)
            .thenApply { c ->
                if (useIdsMessages) {
                    c.addIdsMessageListener { connection, header, _, _ ->
                        header?.let { ListenerManager.publishTransferContractEvent(connection, it.transferContract) }
                    }
                }
                // Notify connection listeners
                ListenerManager.publishConnectionEvent(c, this)
                c
            }
    }

    fun makeConnection(): CompletableFuture<AppLayerConnection> {
        connectionShareId?.let {
            return sharedConnections.computeIfAbsent(it) {
                makeConnectionInternal()
            }
        } ?: return makeConnectionInternal()
    }

    fun releaseConnection(connectionFuture: CompletableFuture<AppLayerConnection>) {
        connectionShareId?.let { sharedConnections.release(it) } ?: releaseConnectionInternal(connectionFuture)
    }

    override fun createProducer(): Producer {
        return Idscp2ClientProducer(this)
    }

    override fun createConsumer(processor: Processor): org.apache.camel.Consumer {
        return Idscp2ClientConsumer(this, processor)
    }

    public override fun doStart() {
        LOG.debug("Starting IDSCP2 client endpoint $endpointUri")
        val remainingMatcher = URI_REGEX.matcher(remaining)
        require(remainingMatcher.matches()) { "$remaining is not a valid URI remainder, must be \"host:port\"." }
        val matchResult = remainingMatcher.toMatchResult()
        val host = matchResult.group(1)
        val port = matchResult.group(2)?.toInt() ?: NativeTlsConfiguration.DEFAULT_SERVER_PORT

        // create attestation config
        val localAttestationConfig = AttestationConfig.Builder()
            .setSupportedRaSuite(supportedRaSuites.split('|').toTypedArray())
            .setExpectedRaSuite(expectedRaSuites.split('|').toTypedArray())
            .setRaTimeoutDelay(dapsRaTimeoutDelay ?: AttestationConfig.DEFAULT_RA_TIMEOUT_DELAY.toLong())
            .build()

        // create daps config builder
        val dapsDriverConfigBuilder = AisecDapsDriverConfig.Builder()
            .setDapsUrl(Utils.dapsUrlProducer())

        // secure channel config
        val secureChannelConfigBuilder = NativeTlsConfiguration.Builder()
            .setHost(host)
            .setServerPort(port)

        @Suppress("DEPRECATION")
        (transportSslContextParameters ?: sslContextParameters)?.let {
            secureChannelConfigBuilder.apply {
                setKeyPassword(
                    it.keyManagers?.keyPassword?.toCharArray()
                        ?: "password".toCharArray()
                )
                it.keyManagers?.keyStore?.resource?.let { setKeyStorePath(Paths.get(it)) }
                it.keyManagers?.keyStore?.type?.let { setKeyStoreKeyType(it) }
                setKeyStorePassword(
                    it.keyManagers?.keyStore?.password?.toCharArray()
                        ?: "password".toCharArray()
                )
                it.trustManagers?.trustManager?.let { setTrustManager(it) }
                it.trustManagers?.keyStore?.resource?.let { setTrustStorePath(Paths.get(it)) }
                setTrustStorePassword(
                    it.trustManagers?.keyStore?.password?.toCharArray()
                        ?: "password".toCharArray()
                )
                setCertificateAlias(it.certAlias ?: "1")
            }
        }

        @Suppress("DEPRECATION")
        (dapsSslContextParameters ?: sslContextParameters)?.let {
            dapsDriverConfigBuilder.apply {
                setKeyPassword(
                    it.keyManagers?.keyPassword?.toCharArray()
                        ?: "password".toCharArray()
                )
                it.keyManagers?.keyStore?.resource?.let { setKeyStorePath(Paths.get(it)) }
                setKeyStorePassword(
                    it.keyManagers?.keyStore?.password?.toCharArray()
                        ?: "password".toCharArray()
                )
                it.trustManagers?.trustManager?.let { setTrustManager(it) }
                it.trustManagers?.keyStore?.resource?.let { setTrustStorePath(Paths.get(it)) }
                setTrustStorePassword(
                    it.trustManagers?.keyStore?.password?.toCharArray()
                        ?: "password".toCharArray()
                )
                setKeyAlias(it.certAlias ?: "1")
            }
        }

        // create idscp configuration
        clientConfiguration = Idscp2Configuration.Builder()
            .setAttestationConfig(localAttestationConfig)
            .setDapsDriver(AisecDapsDriver(dapsDriverConfigBuilder.build()))
            .build()

        secureChannelDriver = NativeTLSDriver()
        secureChannelConfig = secureChannelConfigBuilder.build()
    }

    public override fun doStop() {
        LOG.debug("Stopping IDSCP2 client endpoint $endpointUri")
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(Idscp2ClientEndpoint::class.java)
        private val URI_REGEX = Pattern.compile("(.*?)(?::(\\d+))?/?$")
        private val sharedConnections = RefCountingHashMap<String, CompletableFuture<AppLayerConnection>> {
            releaseConnectionInternal(it)
        }

        private fun releaseConnectionInternal(connectionFuture: CompletableFuture<AppLayerConnection>) {
            if (connectionFuture.isDone) {
                // Exceptional completion includes cancellation
                if (!connectionFuture.isCompletedExceptionally) {
                    connectionFuture.get().close()
                }
            } else {
                connectionFuture.cancel(true)
            }
        }
    }
}
