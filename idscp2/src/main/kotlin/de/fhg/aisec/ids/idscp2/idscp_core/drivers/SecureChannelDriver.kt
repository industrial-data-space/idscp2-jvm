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
package de.fhg.aisec.ids.idscp2.idscp_core.drivers

import de.fhg.aisec.ids.idscp2.idscp_core.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_connection.Idscp2Connection
import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_server.ServerConnectionListener
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.FSM
import java.util.concurrent.CompletableFuture

/**
 * An interface for the IDSCP2 SecureChannelDriver class, that implements a connect() function
 * for IDSCP2 clients and a listen() function for IDSCP2 servers to connect the underlying layer
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
interface SecureChannelDriver<CC : Idscp2Connection, SecureChannelConfiguration> {
    /*
     * Asynchronous method to create a secure connection to a secure server
     */
    fun connect(
        connectionFactory: (FSM, String) -> CC,
        configuration: Idscp2Configuration,
        secureChannelConfig: SecureChannelConfiguration
    ): CompletableFuture<CC>

    /*
     * Starting a secure server
     */
    fun listen(
        connectionListenerPromise: CompletableFuture<ServerConnectionListener<CC>>,
        secureChannelConfig: SecureChannelConfiguration,
        serverConfiguration: Idscp2Configuration,
        connectionFactory: (FSM, String) -> CC
    ): SecureServer
}
