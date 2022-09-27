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
package de.fhg.aisec.ids.idscp2.core.drivers

import de.fhg.aisec.ids.idscp2.core.fsm.fsmListeners.RaProverFsmListener
import org.slf4j.LoggerFactory

/**
 * An abstract RaProverDriver class that creates a RA prover driver thread and proves itself to
 * the peer connector using remote attestation
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
abstract class RaProverDriver<in PC>(protected val fsmListener: RaProverFsmListener) : Thread() {
    protected var running = true

    /*
     * Delegate an IDSCP2 message to the RaProver driver
     */
    open fun delegate(message: ByteArray) {}

    /*
     * Terminate and cancel the RaProver driver
     */
    fun terminate() {
        running = false
        interrupt()
    }

    open fun setConfig(config: PC) {
        LOG.warn("Method 'setConfig' for RaProverDriver is not implemented")
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(RaProverDriver::class.java)
    }
}
