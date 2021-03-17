/*-
 * ========================LICENSE_START=================================
 * idscp2
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
package de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_server

import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_connection.Idscp2Connection

/**
 * A ServerConnectionListener interface for the Idscp2Server to get notification about
 * Idscp2Connection lifetimes in an isolated way
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
interface ServerConnectionListener<CC : Idscp2Connection> {
    fun onConnectionCreated(connection: CC)
    fun onConnectionClose(connection: CC)
}
