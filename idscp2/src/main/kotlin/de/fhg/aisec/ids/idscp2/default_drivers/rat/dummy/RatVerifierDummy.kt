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
package de.fhg.aisec.ids.idscp2.default_drivers.rat.dummy

import de.fhg.aisec.ids.idscp2.idscp_core.drivers.RatVerifierDriver
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.InternalControlMessage
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.fsmListeners.RatVerifierFsmListener
import org.slf4j.LoggerFactory
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue

/**
 * A RatVerifier dummy that exchanges messages with a remote RatProver dummy
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class RatVerifierDummy(fsmListener: RatVerifierFsmListener) : RatVerifierDriver<Unit>(fsmListener) {
    private val queue: BlockingQueue<ByteArray> = LinkedBlockingQueue()
    override fun delegate(message: ByteArray) {
        queue.add(message)
        if (LOG.isDebugEnabled) {
            LOG.debug("Delegated to Verifier")
        }
    }

    override fun run() {
        @Suppress("UNUSED_VARIABLE") val dat = fsmListener.remotePeerDat
        var countDown = 2
        while (running) {
            try {
                sleep(1000)
                if (LOG.isDebugEnabled) {
                    LOG.debug("Verifier waits")
                }
                queue.take()
                if (LOG.isDebugEnabled) {
                    LOG.debug("Verifier receives, send something")
                }
                fsmListener.onRatVerifierMessage(
                    InternalControlMessage.RAT_VERIFIER_MSG,
                    "test".toByteArray()
                )
                if (--countDown == 0) break
            } catch (e: InterruptedException) {
                if (running) {
                    fsmListener.onRatVerifierMessage(InternalControlMessage.RAT_VERIFIER_FAILED)
                }
                return
            }
        }
        fsmListener.onRatVerifierMessage(InternalControlMessage.RAT_VERIFIER_OK)
    }

    companion object {
        const val RAT_VERIFIER_DUMMY_ID = "Dummy"
        private val LOG = LoggerFactory.getLogger(RatVerifierDummy::class.java)
    }
}
