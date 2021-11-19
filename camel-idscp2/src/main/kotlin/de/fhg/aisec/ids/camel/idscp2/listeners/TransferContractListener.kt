package de.fhg.aisec.ids.camel.idscp2.listeners

import de.fhg.aisec.ids.idscp2.app_layer.AppLayerConnection
import java.net.URI

fun interface TransferContractListener {
    fun onTransferContractChange(connection: AppLayerConnection, transferContract: URI?)
}
