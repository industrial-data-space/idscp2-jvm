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
package de.fhg.aisec.ids.camel.idscp2.listeners

import de.fhg.aisec.ids.camel.idscp2.client.Idscp2ClientEndpoint
import de.fhg.aisec.ids.camel.idscp2.server.Idscp2ServerEndpoint
import de.fhg.aisec.ids.idscp2.applayer.AppLayerConnection

interface ConnectionListener {
    fun onClientConnection(connection: AppLayerConnection, endpoint: Idscp2ClientEndpoint)
    fun onServerConnection(connection: AppLayerConnection, endpoint: Idscp2ServerEndpoint)
}
