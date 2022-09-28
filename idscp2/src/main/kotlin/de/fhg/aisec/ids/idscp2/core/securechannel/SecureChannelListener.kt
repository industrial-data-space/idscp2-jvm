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
package de.fhg.aisec.ids.idscp2.core.securechannel

/**
 * An interface for a secure channel listener, implemented by the secure channel
 */
interface SecureChannelListener {
    /*
     * Delegate data from secure channel endpoint to the secure channel
     */
    fun onMessage(data: ByteArray)

    /*
     * Delegate an error from an secure channel endpoint to the secure channel
     */
    fun onError(t: Throwable)

    /*
     * Notify secure channel that secure channel endpoint has been closed
     */
    fun onClose()
}
