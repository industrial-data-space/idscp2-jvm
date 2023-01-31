/*-
 * ========================LICENSE_START=================================
 * idscp2-core
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

import de.fhg.aisec.ids.idscp2.api.drivers.RaVerifierDriver
import de.fhg.aisec.ids.idscp2.api.fsm.InternalControlMessage
import de.fhg.aisec.ids.idscp2.api.fsm.RaVerifierFsmListener
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue

/**
 * A RaVerifier dummy that exchanges messages with a remote RaProver dummy
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 * @author Michael Lux (michael.lux@aisec.fraunhofer.de)
 */
@Deprecated("""This legacy remote attestation ("Dummy") sends useless messages. Use "Dummy2" instead.""")
class RaVerifierDummy(fsmListener: RaVerifierFsmListener) : RaVerifierDriver<Unit>(fsmListener) {
    private val queue: BlockingQueue<ByteArray> = LinkedBlockingQueue()

    override fun delegate(message: ByteArray) {
        queue.add(message)
    }

    override fun run() {
        var countDown = 2
        while (running) {
            try {
                queue.take()
                fsmListener.onRaVerifierMessage(
                    InternalControlMessage.RA_VERIFIER_MSG,
                    "test".toByteArray()
                )
                if (--countDown == 0) break
            } catch (e: InterruptedException) {
                if (running) {
                    fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_FAILED)
                }
                return
            }
        }
        fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_OK)
    }

    companion object {
        const val RA_VERIFIER_DUMMY_ID = "Dummy"
    }
}
