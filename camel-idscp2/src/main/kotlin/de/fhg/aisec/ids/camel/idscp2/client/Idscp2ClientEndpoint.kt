/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.fhg.aisec.ids.camel.idscp2.client

import de.fhg.aisec.ids.api.settings.Settings
import de.fhg.aisec.ids.camel.idscp2.Idscp2OsgiComponent
import de.fhg.aisec.ids.idscp2.Idscp2EndpointListener
import de.fhg.aisec.ids.idscp2.drivers.default_driver_impl.daps.DefaultDapsDriver
import de.fhg.aisec.ids.idscp2.drivers.default_driver_impl.daps.DefaultDapsDriverConfig
import de.fhg.aisec.ids.idscp2.drivers.default_driver_impl.secure_channel.NativeTLSDriver
import de.fhg.aisec.ids.idscp2.idscp_core.Idscp2Connection
import de.fhg.aisec.ids.idscp2.idscp_core.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.idscp_core.configuration.Idscp2Settings
import org.apache.camel.Processor
import org.apache.camel.Producer
import org.apache.camel.spi.UriEndpoint
import org.apache.camel.support.DefaultEndpoint
import org.slf4j.LoggerFactory
import java.util.*
import java.util.regex.Pattern

@UriEndpoint(
        scheme = "idscp2client",
        title = "IDSCP2 Client Socket",
        syntax = "idscp2client://host:port",
        label = "ids"
)
class Idscp2ClientEndpoint(uri: String?, remaining: String, component: Idscp2ClientComponent?) :
        DefaultEndpoint(uri, component), Idscp2EndpointListener {
    private val clientConfiguration: Idscp2Configuration
    private val clientSettings: Idscp2Settings
    private var connection: Idscp2Connection? = null
    private val consumers: MutableSet<Idscp2ClientConsumer> = HashSet()

    init {
        val settings: Settings = Idscp2OsgiComponent.getSettings()
        val remainingMatcher = URI_REGEX.matcher(remaining)
        require(remainingMatcher.matches()) { "$remaining is not a valid URI remainder, must be \"host:port\"." }
        val matchResult = remainingMatcher.toMatchResult()
        val host = matchResult.group(1)
        val port = matchResult.group(2).toInt()
        clientSettings = Idscp2Settings.Builder()
                .setHost(host)
                .setServerPort(port)
                .setKeyStorePath("etc/idscp2/aisecconnector1-keystore.jks")
                .setTrustStorePath("etc/idscp2/client-truststore_new.jks")
                .setCertificateAlias("1.0.1")
                .setDapsKeyAlias("1")
                .setRatTimeoutDelay(300)
                .build()
        val config = DefaultDapsDriverConfig.Builder()
                .setConnectorUUID("edc5d7b3-a398-48f0-abb0-3751530c4fed")
                .setKeyStorePath(clientSettings.keyStorePath)
                .setTrustStorePath(clientSettings.trustStorePath)
                .setKeyStorePassword(clientSettings.keyStorePassword)
                .setTrustStorePassword(clientSettings.trustStorePassword)
                .setKeyAlias(clientSettings.dapsKeyAlias)
                .setDapsUrl(settings.connectorConfig.dapsUrl)
                .build()
        clientConfiguration = Idscp2Configuration(
                this,
                clientSettings,
                DefaultDapsDriver(config),
                NativeTLSDriver()
        )
    }

    @Synchronized
    fun addConsumer(consumer: Idscp2ClientConsumer) {
        consumers.add(consumer)
        connection?.addGenericMessageListener(consumer)
    }

    @Synchronized
    fun removeConsumer(consumer: Idscp2ClientConsumer) {
        consumers.remove(consumer)
        connection?.removeGenericMessageListener(consumer)
    }

    @Synchronized
    fun sendMessage(type: String, body: ByteArray) {
        connection?.send(type, body)
    }

    @Synchronized
    override fun createProducer(): Producer {
        return Idscp2ClientProducer(this)
    }

    @Synchronized
    override fun createConsumer(processor: Processor): org.apache.camel.Consumer {
        return Idscp2ClientConsumer(this, processor)
    }

    @Synchronized
    override fun onConnection(connection: Idscp2Connection) {
        LOG.debug("New IDSCP2 connection on $endpointUri, register consumer listeners")
        consumers.forEach { connection.addGenericMessageListener(it) }
    }

    override fun onError(error: String) {
        LOG.error("Error in IDSCP2 client endpoint $endpointUri:\n$error")
    }

    @Synchronized
    public override fun doStart() {
        LOG.debug("Starting IDSCP2 client endpoint $endpointUri")
        clientConfiguration.connect(clientSettings)
    }

    @Synchronized
    public override fun doStop() {
        LOG.debug("Stopping IDSCP2 client endpoint $endpointUri")
        connection?.close()
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(Idscp2ClientEndpoint::class.java)
        private val URI_REGEX = Pattern.compile("(.*?):(\\d+)$")
    }
}