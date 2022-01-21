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
package de.fhg.aisec.ids.idscp2.default_drivers.remote_attestation.`null`

import de.fhg.aisec.ids.idscp2.idscp_core.drivers.RaVerifierDriver
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.InternalControlMessage
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.fsmListeners.RaVerifierFsmListener
import org.slf4j.LoggerFactory
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue

/**
 * A RaVerifier that exchanges messages with a remote RaProver dummy
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class NullRaVerifier(fsmListener: RaVerifierFsmListener) : RaVerifierDriver<Unit>(fsmListener) {
    private val queue: BlockingQueue<ByteArray> = LinkedBlockingQueue()
    override fun delegate(message: ByteArray) {
        queue.add(message)
        if (LOG.isDebugEnabled) {
            LOG.debug("Delegated to verifier")
        }
    }

    override fun run() {
        try {
            queue.take()
        } catch (e: InterruptedException) {
            if (running) {
                LOG.warn("NullRaVerifier failed")
                fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_FAILED)
            }
            return
        }
        fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_MSG, "".toByteArray())
        fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_OK)
    }

    companion object {
        const val NULL_RA_VERIFIER_ID = "NullRa"
        private val LOG = LoggerFactory.getLogger(NullRaVerifier::class.java)
    }
}
