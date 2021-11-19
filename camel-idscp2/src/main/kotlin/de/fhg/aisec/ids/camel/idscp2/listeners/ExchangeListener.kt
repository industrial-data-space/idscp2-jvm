package de.fhg.aisec.ids.camel.idscp2.listeners

import de.fhg.aisec.ids.idscp2.app_layer.AppLayerConnection
import org.apache.camel.Exchange

fun interface ExchangeListener {
    fun onExchange(connection: AppLayerConnection, exchange: Exchange)
}
