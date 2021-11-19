package de.fhg.aisec.ids.camel.idscp2

import de.fhg.aisec.ids.camel.idscp2.listeners.ExchangeListener
import de.fhg.aisec.ids.camel.idscp2.listeners.TransferContractListener
import de.fhg.aisec.ids.idscp2.app_layer.AppLayerConnection
import org.apache.camel.Exchange
import java.net.URI

object ListenerManager {
    private val exchangeListeners = HashSet<ExchangeListener>()
    private val transferContractListeners = HashSet<TransferContractListener>()

    fun addExchangeListener(listener: ExchangeListener) {
        exchangeListeners += listener
    }

    fun addTransferContractListener(listener: TransferContractListener) {
        transferContractListeners += listener
    }

    fun removeExchangeListener(listener: ExchangeListener) {
        exchangeListeners -= listener
    }

    fun removeTransferContractListener(listener: TransferContractListener) {
        transferContractListeners -= listener
    }

    fun publishExchangeEvent(connection: AppLayerConnection, exchange: Exchange) {
        exchangeListeners.forEach { it.onExchange(connection, exchange) }
    }

    fun publishTransferContractEvent(connection: AppLayerConnection, contract: URI?) {
        transferContractListeners.forEach { it.onTransferContractChange(connection, contract) }
    }
}
