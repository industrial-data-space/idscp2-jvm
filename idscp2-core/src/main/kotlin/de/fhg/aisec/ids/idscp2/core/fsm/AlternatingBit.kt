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
package de.fhg.aisec.ids.idscp2.core.fsm

/**
 * Implementation of an alternating bit protocol for reliability
 * see (https://en.wikipedia.org/wiki/Alternating_bit_protocol)
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */

class AlternatingBit(value: Boolean = false) {
    enum class Bit {
        ZERO, ONE
    }

    private var bit: Bit

    init {
        if (value) {
            this.bit = Bit.ONE
        } else {
            this.bit = Bit.ZERO
        }
    }

    fun alternate() {
        bit = if (bit == Bit.ZERO) {
            Bit.ONE
        } else {
            Bit.ZERO
        }
    }

    fun asBoolean(): Boolean {
        return this.bit != Bit.ZERO
    }
}
