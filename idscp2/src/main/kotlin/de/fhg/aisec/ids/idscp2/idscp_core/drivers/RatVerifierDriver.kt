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
package de.fhg.aisec.ids.idscp2.idscp_core.drivers

import de.fhg.aisec.ids.idscp2.idscp_core.fsm.fsmListeners.RatVerifierFsmListener
import org.slf4j.LoggerFactory

/**
 * An abstract RatVerifierDriver class that creates a rat verifier driver thread and verifier the
 * peer connector using remote attestation
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
abstract class RatVerifierDriver<in VC>(protected val fsmListener: RatVerifierFsmListener) : Thread() {
    protected var running = true

    /*
     * Delegate the IDSCP2 message to the RatVerifier driver
     */
    open fun delegate(message: ByteArray) {}

    /*
     * Terminate and cancel the RatVerifier driver
     */
    fun terminate() {
        running = false
        interrupt()
    }

    open fun setConfig(config: VC) {
        LOG.warn("Method 'setConfig' for RatVerifierDriver is not implemented")
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(RatVerifierDriver::class.java)
    }
}
