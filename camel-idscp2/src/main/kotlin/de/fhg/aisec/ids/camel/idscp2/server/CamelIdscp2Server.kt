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

import de.fhg.aisec.ids.camel.idscp2.ListenerManager
import de.fhg.aisec.ids.idscp2.app_layer.AppLayerConnection
import de.fhg.aisec.ids.idscp2.default_drivers.secure_channel.tlsv1_3.NativeTLSDriver
import de.fhg.aisec.ids.idscp2.default_drivers.secure_channel.tlsv1_3.NativeTlsConfiguration
import de.fhg.aisec.ids.idscp2.idscp_core.api.Idscp2EndpointListener
import de.fhg.aisec.ids.idscp2.idscp_core.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_server.Idscp2Server
import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_server.Idscp2ServerFactory
import java.util.Collections

class CamelIdscp2Server(
    serverConfiguration: Idscp2Configuration,
    nativeTlsConfiguration: NativeTlsConfiguration,
    private val useIdsMessages: Boolean
) :
    Idscp2EndpointListener<AppLayerConnection> {
    private val server: Idscp2Server<AppLayerConnection>
    val listeners: MutableSet<Idscp2EndpointListener<AppLayerConnection>> = Collections.synchronizedSet(HashSet())

    init {
        val serverFactory = Idscp2ServerFactory(
            ::AppLayerConnection,
            this,
            serverConfiguration,
            NativeTLSDriver(),
            nativeTlsConfiguration
        )
        server = serverFactory.listen()
    }

    override fun onConnection(connection: AppLayerConnection) {
        if (useIdsMessages) {
            connection.addIdsMessageListener { c, header, _, _ ->
                header?.let {
                    ListenerManager.publishTransferContractEvent(c, it.transferContract)
                }
            }
        }
        listeners.forEach { it.onConnection(connection) }
    }

    val allConnections: Collection<AppLayerConnection> = server.allConnections

    fun terminate() {
        server.terminate()
    }
}
