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
package de.fhg.aisec.ids.idscp2.idscp_core.fsm.fsmListeners

import java.security.cert.X509Certificate

/**
 * An FSM Listener Interface for the SecureChannel driver implemented by the FSM to restrict FSM API to
 * the SecureChannel drivers class of the IDSCP2
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
interface ScFsmListener {

    /**
     * A method for providing IDSCP2 data from the secure channel to the FSM
     */
    fun onMessage(data: ByteArray)

    /**
     * A method for providing internal SC errors to the fsm
     */
    fun onError(t: Throwable)

    /**
     * A method for notifying the fsm about closure of the secure channel
     */
    fun onClose()

    /**
     * A method for providing the peer certificate from the secure channel to the FSM
     */
    fun setPeerX509Certificate(certificate: X509Certificate)
}
