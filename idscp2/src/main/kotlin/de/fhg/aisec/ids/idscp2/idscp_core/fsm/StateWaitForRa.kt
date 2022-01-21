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
package de.fhg.aisec.ids.idscp2.idscp_core.fsm

import de.fhg.aisec.ids.idscp2.idscp_core.fsm.FSM.FsmState
import de.fhg.aisec.ids.idscp2.idscp_core.messages.Idscp2MessageHelper
import de.fhg.aisec.ids.idscp2.messages.IDSCP2.IdscpClose.CloseCause
import de.fhg.aisec.ids.idscp2.messages.IDSCP2.IdscpMessage
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory

/**
 * The Wait_For_Ra State of the FSM of the IDSCP2 protocol.
 * Waits for the RaProver and RaVerifier Result to decide whether the connection will be
 * established
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class StateWaitForRa(
    fsm: FSM,
    handshakeTimer: StaticTimer,
    verifierHandshakeTimer: StaticTimer,
    proverHandshakeTimer: StaticTimer,
    raTimer: StaticTimer
) : State() {
    override fun runEntryCode(fsm: FSM) {
        if (LOG.isTraceEnabled) {
            LOG.trace("Switched to state STATE_WAIT_FOR_RA")
        }
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(StateWaitForRa::class.java)
    }

    init {

        /*---------------------------------------------------
         * STATE_WAIT_FOR_RA - Transition Description
         * ---------------------------------------------------
         * onICM: error ---> {raP.stop(), raV.stop(), timeouts.stop()} ---> IDSCP_CLOSED
         * onICM: stop ---> {raP.stop(), raV.stop(), timeouts.stop(), send IDSCP_CLOSE} ---> IDSCP_CLOSED
         * onICM: ra_prover_ok ---> {} ---> STATE_WAIT_FOR_RA_VERIFIER
         * onICM: ra_verifier_ok ---> {set ra timeout} ---> STATE_WAIT_FOR_RA_PROVER
         * onICM: ra_prover_failed ---> {raV.stop(), timeouts.stop(), send IDSCP_CLOSE} ---> STATE_CLOSED
         * onICM: ra_verifier_failed ---> {raP.stop(), timeouts.stop(), send IDSCP_CLOSE} ---> STATE_CLOSED
         * onICM: ra_prover_msg ---> {send IDSCP_RA_PROVER} ---> STATE_WAIT_FOR_RA
         * onICM: ra_verifier_msg ---> {send IDSCP_RA_VERIFIER} ---> STATE_WAIT_FOR_RA
         * onICM: dat_timeout ---> {send DAT_EXPIRED, raV.cancel()} ---> STATE_WAIT_FOR_DAT_AND_RA
         * onICM: handshake_timeout ---> {send IDSCP_CLOSE} ---> STATE_CLOSED
         * onMessage: IDSCP_ACK ---> {cancel Ack flag} ---> STATE_WAIT_FOR_RA
         * onMessage: IDSCP_RA_VERIFIER ---> {delegate to RA_PROVER} ---> STATE_WAIT_FOR_RA
         * onMessage: IDSCP_RA_PROVER ---> {delegate to RA_VERIFIER} ---> STATE_WAIT_FOR_RA
         * onMessage: IDSCP_DAT_EXPIRED ---> {send DAT, raP.restart()} ---> STATE_WAIT_FOR_RA
         * onMessage: IDSCP_CLOSE ---> {raP.stop(), raV.stop(), timeouts.stop()} ---> IDSCP_CLOSED
         * ALL_OTHER_MESSAGES ---> {} ---> STATE_WAIT_FOR_RA
         * --------------------------------------------------- */
        addTransition(
            InternalControlMessage.ERROR.value,
            Transition {
                LOG.warn("An internal control error occurred")
                FSM.FsmResult(FSM.FsmResultCode.OK, fsm.getState(FsmState.STATE_CLOSED))
            }
        )

        addTransition(
            InternalControlMessage.IDSCP_STOP.value,
            Transition {
                if (LOG.isTraceEnabled) {
                    LOG.trace("Send IDSCP_CLOSE")
                }
                fsm.sendFromFSM(
                    Idscp2MessageHelper.createIdscpCloseMessage(
                        "User close",
                        CloseCause.USER_SHUTDOWN
                    )
                )
                FSM.FsmResult(FSM.FsmResultCode.OK, fsm.getState(FsmState.STATE_CLOSED))
            }
        )

        addTransition(
            InternalControlMessage.SEND_DATA.value,
            Transition {
                FSM.FsmResult(FSM.FsmResultCode.NOT_CONNECTED, this)
            }
        )

        addTransition(
            InternalControlMessage.REPEAT_RA.value,
            Transition {
                // nothing to do, currently attestating
                FSM.FsmResult(FSM.FsmResultCode.OK, this)
            }
        )

        addTransition(
            InternalControlMessage.RA_PROVER_OK.value,
            Transition {
                if (LOG.isTraceEnabled) {
                    LOG.trace("Received RA_PROVER OK")
                }
                proverHandshakeTimer.cancelTimeout()
                FSM.FsmResult(FSM.FsmResultCode.OK, fsm.getState(FsmState.STATE_WAIT_FOR_RA_VERIFIER))
            }
        )

        addTransition(
            InternalControlMessage.RA_VERIFIER_OK.value,
            Transition {
                if (LOG.isTraceEnabled) {
                    LOG.trace("Received RA_VERIFIER OK")
                }
                verifierHandshakeTimer.cancelTimeout()
                raTimer.resetTimeout()
                FSM.FsmResult(FSM.FsmResultCode.OK, fsm.getState(FsmState.STATE_WAIT_FOR_RA_PROVER))
            }
        )

        addTransition(
            InternalControlMessage.RA_PROVER_FAILED.value,
            Transition {
                LOG.warn("RA_PROVER failed. Send IDSCP_CLOSE")
                fsm.sendFromFSM(
                    Idscp2MessageHelper.createIdscpCloseMessage(
                        "RA_PROVER failed",
                        CloseCause.RA_PROVER_FAILED
                    )
                )
                FSM.FsmResult(FSM.FsmResultCode.OK, fsm.getState(FsmState.STATE_CLOSED))
            }
        )

        addTransition(
            InternalControlMessage.RA_VERIFIER_FAILED.value,
            Transition {
                LOG.warn("RA_VERIFIER failed. Send IDSCP_CLOSE")
                fsm.sendFromFSM(
                    Idscp2MessageHelper.createIdscpCloseMessage(
                        "RA_VERIFIER failed",
                        CloseCause.RA_VERIFIER_FAILED
                    )
                )
                FSM.FsmResult(FSM.FsmResultCode.OK, fsm.getState(FsmState.STATE_CLOSED))
            }
        )

        addTransition(
            InternalControlMessage.RA_PROVER_MSG.value,
            Transition { event: Event ->
                if (LOG.isTraceEnabled) {
                    LOG.trace("Send IDSCP_RA_PROVER")
                }
                if (!fsm.sendFromFSM(event.idscpMessage)) {
                    LOG.warn("Cannot send RA prover message")
                    return@Transition FSM.FsmResult(FSM.FsmResultCode.IO_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }
                FSM.FsmResult(FSM.FsmResultCode.OK, this)
            }
        )

        addTransition(
            InternalControlMessage.RA_VERIFIER_MSG.value,
            Transition { event: Event ->
                if (LOG.isTraceEnabled) {
                    LOG.trace("Send IDSCP_RA_VERIFIER")
                }
                if (!fsm.sendFromFSM(event.idscpMessage)) {
                    LOG.warn("Cannot send RA verifier message")
                    return@Transition FSM.FsmResult(FSM.FsmResultCode.IO_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }
                FSM.FsmResult(FSM.FsmResultCode.OK, this)
            }
        )

        addTransition(
            InternalControlMessage.DAT_TIMER_EXPIRED.value,
            Transition {
                if (LOG.isDebugEnabled) {
                    LOG.debug("DAT expired, request new DAT from peer and trigger a re-attestation")
                }
                if (LOG.isTraceEnabled) {
                    LOG.trace("Send IDSCP_DAT_EXPIRED and cancel RA_VERIFIER")
                }
                fsm.stopRaVerifierDriver()
                if (!fsm.sendFromFSM(Idscp2MessageHelper.createIdscpDatExpiredMessage())) {
                    LOG.warn("Cannot send DatExpired message")
                    return@Transition FSM.FsmResult(FSM.FsmResultCode.IO_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }
                if (LOG.isTraceEnabled) {
                    LOG.trace("Start Handshake Timer")
                }
                handshakeTimer.resetTimeout()
                FSM.FsmResult(FSM.FsmResultCode.OK, fsm.getState(FsmState.STATE_WAIT_FOR_DAT_AND_RA))
            }
        )

        addTransition(
            InternalControlMessage.TIMEOUT.value,
            Transition {
                LOG.warn("Handshake timeout occurred. Send IDSCP_CLOSE")
                fsm.sendFromFSM(
                    Idscp2MessageHelper.createIdscpCloseMessage(
                        "Handshake timeout",
                        CloseCause.TIMEOUT
                    )
                )
                FSM.FsmResult(FSM.FsmResultCode.OK, fsm.getState(FsmState.STATE_CLOSED))
            }
        )

        addTransition(
            IdscpMessage.IDSCPACK_FIELD_NUMBER,
            Transition {
                fsm.recvAck(it.idscpMessage.idscpAck)
                FSM.FsmResult(FSM.FsmResultCode.OK, this)
            }
        )

        addTransition(
            IdscpMessage.IDSCPRAVERIFIER_FIELD_NUMBER,
            Transition { event: Event ->
                if (LOG.isTraceEnabled) {
                    LOG.trace("Delegate received IDSCP_RA_VERIFIER to RA_PROVER")
                }

                if (!event.idscpMessage.hasIdscpRaVerifier()) {
                    // this should never happen
                    LOG.warn("IDSCP_RA_Verifier message not available")
                    return@Transition FSM.FsmResult(FSM.FsmResultCode.RA_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }

                fsm.raProverDriver?.let {
                    // Run in async fire-and-forget coroutine to avoid cycles caused by protocol misuse
                    GlobalScope.launch {
                        it.delegate(event.idscpMessage.idscpRaVerifier.data.toByteArray())
                    }
                } ?: run {
                    LOG.warn("RaProverDriver not available")
                    return@Transition FSM.FsmResult(FSM.FsmResultCode.RA_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }

                FSM.FsmResult(FSM.FsmResultCode.OK, this)
            }
        )

        addTransition(
            IdscpMessage.IDSCPRAPROVER_FIELD_NUMBER,
            Transition { event: Event ->
                if (LOG.isTraceEnabled) {
                    LOG.trace("Delegate received IDSCP_RA_PROVER to RA_VERIFIER")
                }

                if (!event.idscpMessage.hasIdscpRaProver()) {
                    // this should never happen
                    LOG.warn("IDSCP_RA_PROVER message not available")
                    return@Transition FSM.FsmResult(FSM.FsmResultCode.RA_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }

                fsm.raVerifierDriver?.let {
                    // Run in async fire-and-forget coroutine to avoid cycles caused by protocol misuse
                    GlobalScope.launch {
                        it.delegate(event.idscpMessage.idscpRaProver.data.toByteArray())
                    }
                } ?: run {
                    LOG.warn("RaVerifierDriver not available")
                    return@Transition FSM.FsmResult(FSM.FsmResultCode.RA_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }

                FSM.FsmResult(FSM.FsmResultCode.OK, this)
            }
        )

        addTransition(
            IdscpMessage.IDSCPDATEXPIRED_FIELD_NUMBER,
            Transition {
                if (LOG.isDebugEnabled) {
                    LOG.debug("Peer is requesting a new DAT, followed by a re-attestation")
                }
                if (!fsm.sendFromFSM(Idscp2MessageHelper.createIdscpDatMessage(fsm.dynamicAttributeToken))) {
                    LOG.warn("Cannot send DAT message")
                    return@Transition FSM.FsmResult(FSM.FsmResultCode.IO_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }

                if (!fsm.restartRaProverDriver()) {
                    LOG.warn("Cannot run RA prover, close idscp connection")
                    return@Transition FSM.FsmResult(FSM.FsmResultCode.RA_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }
                FSM.FsmResult(FSM.FsmResultCode.OK, this)
            }
        )

        addTransition(
            IdscpMessage.IDSCPCLOSE_FIELD_NUMBER,
            Transition {
                if (LOG.isTraceEnabled) {
                    LOG.trace("Received IDSCP_CLOSE")
                }
                FSM.FsmResult(FSM.FsmResultCode.OK, fsm.getState(FsmState.STATE_CLOSED))
            }
        )

        setNoTransitionHandler { event: Event? ->
            if (LOG.isTraceEnabled) {
                LOG.trace("No transition available for given event " + event.toString())
                LOG.trace("Stay in state STATE_WAIT_FOR_RA")
            }
            FSM.FsmResult(FSM.FsmResultCode.UNKNOWN_TRANSITION, this)
        }
    }
}
