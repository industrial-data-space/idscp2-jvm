/*-
 * ========================LICENSE_START=================================
 * idscp2
 * %%
 * Copyright (C) 2022 Fraunhofer AISEC
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
package de.fhg.aisec.ids.idscp2.default_drivers.remote_attestation.gramine

import de.fhg.aisec.ids.idscp2.idscp_core.drivers.RaProverDriver
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.InternalControlMessage
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.fsmListeners.RaProverFsmListener
import org.slf4j.LoggerFactory
import java.io.File
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue

/**
 * An RaProver that, when ran by the client, produces an Intel SGX Attestation Report
 * containing the nocne sent by the RaVerifier.
 *
 * @author Andrei-Cosmin Aprodu (andrei-cosmin.aprodu@aisec.fraunhofer.de)
 */
class GramineRaProver(fsmListener: RaProverFsmListener) : RaProverDriver<String>(fsmListener) {
    private val queue: BlockingQueue<ByteArray> = LinkedBlockingQueue()
    private lateinit var currentTarget: String

    override fun delegate(message: ByteArray) {
        queue.add(message)
        if (LOG.isDebugEnabled) {
            LOG.debug("Delegated to prover")
        }
    }

    override fun setConfig(config: String) {
        currentTarget = config
    }

    override fun run() {
        // Only the client can issue an attestation certificate, so we cannot consider
        // the current authentication process symmatrical anymore.
        if (currentTarget == "Server") {
            fsmListener.onRaProverMessage(InternalControlMessage.RA_PROVER_OK)
            return
        }

        try {
            val msg = queue.take().decodeToString()
            if (LOG.isDebugEnabled) {
                LOG.debug("Prover received nonce. Generating certificate...")
            }

            // https://gramine.readthedocs.io/en/stable/attestation.html
            File("/dev/attestation/user_report_data").writeText(msg)
            val quote = File("/dev/attestation/quote").readBytes()

            if (LOG.isDebugEnabled) {
                LOG.debug("Prover sends certificate...")
            }
            fsmListener.onRaProverMessage(
                InternalControlMessage.RA_PROVER_MSG,
                quote
            )
        } catch (e: InterruptedException) {
            if (running) {
                fsmListener.onRaProverMessage(InternalControlMessage.RA_PROVER_FAILED)
            }
            return
        }
        fsmListener.onRaProverMessage(InternalControlMessage.RA_PROVER_OK)
    }

    companion object {
        const val GRAMINE_RA_PROVER_ID = "Gramine"
        private val LOG = LoggerFactory.getLogger(GramineRaProver::class.java)
    }
}
