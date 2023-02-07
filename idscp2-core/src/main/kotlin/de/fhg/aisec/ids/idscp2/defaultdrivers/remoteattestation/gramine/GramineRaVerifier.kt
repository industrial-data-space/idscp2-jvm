/*-
 * ========================LICENSE_START=================================
 * idscp2-core
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
package de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.gramine

import de.fhg.aisec.ids.idscp2.api.drivers.RaVerifierDriver
import de.fhg.aisec.ids.idscp2.api.fsm.InternalControlMessage
import de.fhg.aisec.ids.idscp2.api.fsm.RaVerifierFsmListener
import org.slf4j.LoggerFactory
import java.io.File
import java.lang.ProcessBuilder
import java.security.SecureRandom
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue

/**
 * A RaVerifier that requires the client RaProver to present a valid Intel SGX Attestation Report
 * containing a nonce it sends in the beginning.
 *
 * @author Andrei-Cosmin Aprodu (andrei-cosmin.aprodu@aisec.fraunhofer.de)
 */
class GramineRaVerifier(fsmListener: RaVerifierFsmListener) : RaVerifierDriver<String>(fsmListener) {
    private val queue: BlockingQueue<ByteArray> = LinkedBlockingQueue()
    private lateinit var currentTarget: String

    // TODO: Insert Primary Key corresponding to the current SPID here!
    private val primaryKey = ""

    private fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }

    override fun delegate(message: ByteArray) {
        queue.add(message)
        if (LOG.isDebugEnabled) {
            LOG.debug("Delegated to Gramine Verifier")
        }
    }

    override fun setConfig(config: String) {
        currentTarget = config
    }

    override fun run() {
        // Only the client can issue an attestation certificate, so we cannot consider
        // the current authentication process symmatrical anymore.
        if (currentTarget == "Client") {
            fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_OK)
            return
        }
        if (primaryKey == "") {
            LOG.error("Please enter your Primary Key in order to access the Intel Attestation Services!")
            fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_FAILED)
            return
        }

        val nonceRaw = ByteArray(32)
        SecureRandom().nextBytes(nonceRaw)
        val nonce = nonceRaw.toHexString()

        try {
            if (LOG.isDebugEnabled) {
                LOG.debug("Verifier sends nonce \"${nonce}\"...")
            }
            fsmListener.onRaVerifierMessage(
                InternalControlMessage.RA_VERIFIER_MSG,
                nonce.toByteArray()
            )
            if (LOG.isDebugEnabled) {
                LOG.debug("Verifier waits....")
            }
            val msg = queue.take()
            if (LOG.isDebugEnabled) {
                LOG.debug("Verifier received response. Searching for nonce...")
            }

            File("/tmp/QUOTE").writeBytes(msg)

            // 1st check: verify whether the quote is authentic
            val quoteVerifierProcess = ProcessBuilder("../quote-verifier.sh", primaryKey).start()
            quoteVerifierProcess.waitFor()
            if (String(quoteVerifierProcess.inputStream.readAllBytes()).trim().toInt() != 1) {
                LOG.error("Check 1: Quote not authentic! Aborting...")
                if (running) {
                    fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_FAILED)
                }
                return
            } else {
                LOG.info("Check 1: Quote authentic.")
            }

            // 2nd check: verify whether nonce is included in quote
            // TODO: Include verification step into the Kotlin codebase in future update
            val quoteContents = File("/tmp/QUOTE").readBytes()
            if (quoteContents.copyOfRange(368, 432).toString(Charsets.US_ASCII) != nonce) {
                LOG.error("Check 2: Quote does not contain nonce! Aborting...")
                if (running) {
                    fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_FAILED)
                }
                return
            } else {
                LOG.info("Check 2: Quote contains nonce.")
            }
        } catch (e: InterruptedException) {
            if (running) {
                fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_FAILED)
            }
            return
        }
        fsmListener.onRaVerifierMessage(InternalControlMessage.RA_VERIFIER_OK)
    }

    companion object {
        const val GRAMINE_RA_VERIFIER_ID = "Gramine"
        private val LOG = LoggerFactory.getLogger(GramineRaVerifier::class.java)
    }
}
