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
package de.fhg.aisec.ids.camel.idscp2.server

import de.fhg.aisec.ids.camel.idscp2.Constants.IDSCP2_HEADER
import de.fhg.aisec.ids.camel.idscp2.ListenerManager
import de.fhg.aisec.ids.camel.idscp2.Utils
import de.fhg.aisec.ids.idscp2.app_layer.AppLayerConnection
import de.fhg.aisec.ids.idscp2.app_layer.listeners.GenericMessageListener
import de.fhg.aisec.ids.idscp2.app_layer.listeners.IdsMessageListener
import de.fraunhofer.iais.eis.Message
import org.apache.camel.Processor
import org.apache.camel.support.DefaultConsumer
import org.slf4j.LoggerFactory

/**
 * The IDSCP2 server consumer.
 */
class Idscp2ServerConsumer(private val endpoint: Idscp2ServerEndpoint, processor: Processor) :
    DefaultConsumer(endpoint, processor), GenericMessageListener, IdsMessageListener {
    override fun doStart() {
        super.doStart()
        endpoint.addConsumer(this)
    }

    override fun doStop() {
        endpoint.removeConsumer(this)
        super.doStop()
    }

    override fun onMessage(connection: AppLayerConnection, header: Message?, payload: ByteArray?) {
        if (LOG.isTraceEnabled) {
            LOG.trace("Idscp2ServerConsumer received IdsMessage with header:\n{}", header)
        }
        onMessage(connection, header as Any, payload)
    }

    override fun onMessage(connection: AppLayerConnection, header: String?, payload: ByteArray?) {
        if (LOG.isTraceEnabled) {
            LOG.trace("Idscp2ServerConsumer received GenericMessage with header:\n{}", header)
        }
        onMessage(connection, header as Any, payload)
    }

    private fun onMessage(connection: AppLayerConnection, header: Any?, payload: ByteArray?) {
        val exchange = endpoint.createExchange()
        // Ensures that Exchange has an ID
        exchange.exchangeId
        ListenerManager.publishExchangeEvent(connection, exchange)
        try {
            createUoW(exchange)
            // Set relevant information
            exchange.message.let {
                it.setHeader(IDSCP2_HEADER, header)
                it.setBody(payload, ByteArray::class.java)
            }
            // Do processing
            processor.process(exchange)
            // Handle response
            exchange.message.let {
                val responseHeader = it.getHeader(IDSCP2_HEADER)
                val responseBody = it.getBody(ByteArray::class.java)
                if (responseBody != null || responseHeader != null) {
                    if (endpoint.useIdsMessages) {
                        connection.sendIdsMessage(
                            responseHeader?.let { Utils.finalizeMessage(responseHeader, connection) },
                            responseBody
                        )
                    } else {
                        connection.sendGenericMessage(responseHeader?.toString(), responseBody)
                    }
                }
            }
        } catch (e: Exception) {
            LOG.error("Error in Idscp2ServerConsumer.onMessage()", e)
        } finally {
            doneUoW(exchange)
        }
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(Idscp2ServerConsumer::class.java)
    }
}
