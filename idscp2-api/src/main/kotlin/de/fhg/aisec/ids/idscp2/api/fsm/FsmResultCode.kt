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

enum class FsmResultCode(val value: String) {
    UNKNOWN_TRANSITION("No transition available for given event in current state."),
    FSM_LOCKED("FSM is locked forever."),
    FSM_NOT_STARTED("Handshake was never started."),
    MISSING_DAT("DAT is missing."),
    INVALID_DAT("DAT is invalid."),
    IO_ERROR("Secure channel not available."),
    RA_ERROR("RA error occurred."),
    RA_NEGOTIATION_ERROR("Error during negotiation of RA mechanisms."),
    WOULD_BLOCK("Operation would block until FSM is in state 'ESTABLISHED'"),
    NOT_CONNECTED("Protocol is not in a connected state at the moment."),
    IDSCP_DATA_NOT_CACHED("IdscpData must be buffered in the 'WAIT_FOR_ACK' state."),
    OK("Action succeed.")
}
