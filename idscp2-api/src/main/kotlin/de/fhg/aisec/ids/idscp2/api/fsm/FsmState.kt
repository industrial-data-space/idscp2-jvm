/*-
 * ========================LICENSE_START=================================
 * idscp2-api
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
package de.fhg.aisec.ids.idscp2.api.fsm

enum class FsmState {
    STATE_CLOSED,
    STATE_WAIT_FOR_HELLO,
    STATE_WAIT_FOR_RA,
    STATE_WAIT_FOR_RA_VERIFIER,
    STATE_WAIT_FOR_RA_PROVER,
    STATE_WAIT_FOR_DAT_AND_RA_VERIFIER,
    STATE_WAIT_FOR_DAT_AND_RA,
    STATE_ESTABLISHED,
    STATE_WAIT_FOR_ACK
}
