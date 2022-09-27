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
package de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.dummy

import de.fhg.aisec.ids.idscp2.core.drivers.RaVerifierDriver
import de.fhg.aisec.ids.idscp2.core.fsm.InternalControlMessage
import de.fhg.aisec.ids.idscp2.core.fsm.fsmListeners.RaVerifierFsmListener

/**
 * A RaProver dummy just confirms successful remote attestation.
 *
 * @author Michael Lux (michael.lux@aisec.fraunhofer.de)
 */
class RaVerifierDummy2(fsmListener: RaVerifierFsmListener) : RaVerifierDriver<Unit>(fsmListener) {

    override fun delegate(message: ByteArray) {
    }

    override fun run() {
        fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_OK)
    }

    companion object {
        const val RA_VERIFIER_DUMMY2_ID = "Dummy2"
    }
}
