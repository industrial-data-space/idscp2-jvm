/*-
 * ========================LICENSE_START=================================
 * idscp2-app-layer
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
package de.fhg.aisec.ids.idscp2.app_layer.listeners

import de.fhg.aisec.ids.idscp2.app_layer.AppLayerConnection

fun interface GenericMessageListener {
    fun onMessage(connection: AppLayerConnection, header: String?, payload: ByteArray?, extraHeaders: Map<String, String>?)
}
