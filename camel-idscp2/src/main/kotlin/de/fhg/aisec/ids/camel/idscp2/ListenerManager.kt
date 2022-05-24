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
package de.fhg.aisec.ids.camel.idscp2

import de.fhg.aisec.ids.camel.idscp2.client.Idscp2ClientEndpoint
import de.fhg.aisec.ids.camel.idscp2.listeners.ConnectionListener
import de.fhg.aisec.ids.camel.idscp2.listeners.ExchangeListener
import de.fhg.aisec.ids.camel.idscp2.listeners.TransferContractListener
import de.fhg.aisec.ids.camel.idscp2.server.Idscp2ServerEndpoint
import de.fhg.aisec.ids.idscp2.app_layer.AppLayerConnection
import org.apache.camel.Exchange
import org.apache.camel.support.DefaultEndpoint
import java.net.URI

object ListenerManager {
    private val exchangeListeners = HashSet<ExchangeListener>()
    private val transferContractListeners = HashSet<TransferContractListener>()
    private val connectionListeners = HashSet<ConnectionListener>()

    fun addExchangeListener(listener: ExchangeListener) {
        exchangeListeners += listener
    }

    fun addTransferContractListener(listener: TransferContractListener) {
        transferContractListeners += listener
    }

    fun addConnectionListener(listener: ConnectionListener) {
        connectionListeners += listener
    }

    fun removeExchangeListener(listener: ExchangeListener) {
        exchangeListeners -= listener
    }

    fun removeTransferContractListener(listener: TransferContractListener) {
        transferContractListeners -= listener
    }

    fun removeConnectionListener(listener: ConnectionListener) {
        connectionListeners -= listener
    }

    fun publishExchangeEvent(connection: AppLayerConnection, exchange: Exchange) {
        exchangeListeners.forEach { it.onExchange(connection, exchange) }
    }

    fun publishTransferContractEvent(connection: AppLayerConnection, contract: URI?) {
        transferContractListeners.forEach { it.onTransferContractChange(connection, contract) }
    }

    fun publishConnectionEvent(connection: AppLayerConnection, endpoint: DefaultEndpoint) {
        when (endpoint) {
            is Idscp2ClientEndpoint -> {
                connectionListeners.forEach { it.onClientConnection(connection, endpoint) }
            }
            is Idscp2ServerEndpoint -> {
                connectionListeners.forEach { it.onServerConnection(connection, endpoint) }
            }
            else -> {
                // nothing to do
            }
        }
    }
}
