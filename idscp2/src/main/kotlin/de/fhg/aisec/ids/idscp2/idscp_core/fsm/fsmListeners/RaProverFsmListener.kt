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

import de.fhg.aisec.ids.idscp2.idscp_core.fsm.InternalControlMessage
import java.security.cert.X509Certificate

/**
 * An FSM Listener Interface for the RaProver driver implemented by the FSM to restrict FSM API to
 * the RaProver drivers class of the IDSCP2
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
interface RaProverFsmListener {

    /**
     * A method for providing RaProver messages from the RaProverDriver implementation to the FSM
     */
    fun onRaProverMessage(controlMessage: InternalControlMessage)
    fun onRaProverMessage(controlMessage: InternalControlMessage, raMessage: ByteArray)

    /**
     * Access the remote peer transport certificate from the RA prover
     */
    val remotePeerCertificate: X509Certificate?
}
