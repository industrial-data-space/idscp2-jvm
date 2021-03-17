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
package de.fhg.aisec.ids.idscp2.default_drivers.secure_channel.tlsv1_3.client

/**
 * An interface for DataAvailableListeners, that will be notified when new data has been received
 * at the sslSocket
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
interface DataAvailableListener {
    /*
     * Provide incoming data to listener
     */
    fun onMessage(bytes: ByteArray)

    /*
     * Notify listener that an error has occurred
     */
    fun onError(e: Throwable)

    /*
     * Notify listener that the socket has been closed
     */
    fun onClose()
}
