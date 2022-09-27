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
package de.fhg.aisec.ids.idscp2.core.fsm

import de.fhg.aisec.ids.idscp2.core.drivers.DapsDriver
import de.fhg.aisec.ids.idscp2.core.fsm.FSM.FsmState
import de.fhg.aisec.ids.idscp2.core.messages.Idscp2MessageHelper
import de.fhg.aisec.ids.idscp2.messages.IDSCP2.IdscpClose.CloseCause
import de.fhg.aisec.ids.idscp2.messages.IDSCP2.IdscpMessage
import org.slf4j.LoggerFactory

/**
 * The Wait_For_Dat_And_Ra_Verifier State of the FSM of the IDSCP2 protocol.
 * Wait for a new dynamic attribute token from the peer, since the old one is not valid anymore
 * and waits for the RaVerifier after successful verification of the Dat to decide if the IDSCP2
 * connection will be established
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class StateWaitForDatAndRaVerifier(
    fsm: FSM,
    handshakeTimer: StaticTimer,
    datTimer: DynamicTimer,
    dapsDriver: DapsDriver
) : State() {
    override fun runEntryCode(fsm: FSM) {
        if (LOG.isTraceEnabled) {
            LOG.trace("Set handshake timeout")
        }
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(StateWaitForDatAndRaVerifier::class.java)
    }

    init {

        /*---------------------------------------------------
         * STATE_WAIT_FOR_DAT_AND_RA_VERIFIER - Transition Description
         * ---------------------------------------------------
         * onICM: stop ---> {send IDSCP_CLOSE} ---> STATE_CLOSED
         * onICM: error ---> {} ---> STATE_CLOSED
         * onICM: timeout ---> {send IDSCP_CLOSE} ---> STATE_CLOSED
         * onMessage: IDSCP_ACK ---> {cancel Ack flag} ---> STATE_WAIT_FOR_RA
         * onMessage: IDSCP_CLOSE ---> {} ---> STATE_CLOSED
         * onMessage: IDSCP_DAT(success) --> {verify DAT, set det_timeout, start RA_VERIFIER} ---> STATE_WAIT_FOR_RA_VERIFEIER
         * onMessage: IDSCP_DAT(failed) --> {verify DAT, send IDSCP_CLOSE} ---> STATE_CLOSED
         * onMessage: IDSCP_DAT_EXPIRED ---> {send IDSCP_DAT, start IDSCP_PROVER} ---> STATE_WAIT_FOR_DAT_AND_RA
         * onMessage: IDSCP_RE_RA ---> {start IDSCP_PROVER} ---> STATE_WAIT_FOR_DAT_AND_RA
         * ALL_OTHER_MESSAGES ---> {} ---> STATE_WAIT_FOR_DAT_AND_RA_VERIFIER
         * --------------------------------------------------- */
        addTransition(
            InternalControlMessage.IDSCP_STOP.value,
            Transition {
                if (LOG.isTraceEnabled) {
                    LOG.trace("Send IDSC_CLOSE")
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
            InternalControlMessage.ERROR.value,
            Transition {
                LOG.warn("An internal control error occurred")
                FSM.FsmResult(FSM.FsmResultCode.OK, fsm.getState(FsmState.STATE_CLOSED))
            }
        )

        addTransition(
            InternalControlMessage.REPEAT_RA.value,
            Transition {
                FSM.FsmResult(FSM.FsmResultCode.OK, this)
            }
        )

        addTransition(
            InternalControlMessage.SEND_DATA.value,
            Transition {
                FSM.FsmResult(FSM.FsmResultCode.NOT_CONNECTED, this)
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
            IdscpMessage.IDSCPCLOSE_FIELD_NUMBER,
            Transition {
                if (LOG.isTraceEnabled) {
                    LOG.trace("Received IDSCP_CLOSE")
                }
                FSM.FsmResult(FSM.FsmResultCode.OK, fsm.getState(FsmState.STATE_CLOSED))
            }
        )

        addTransition(
            IdscpMessage.IDSCPDAT_FIELD_NUMBER,
            Transition { event: Event ->

                handshakeTimer.cancelTimeout()
                if (LOG.isTraceEnabled) {
                    LOG.trace("Verify received DAT")
                }

                // check if Dat is available and verify dat
                val dat = event.idscpMessage.idscpDat.token.toByteArray()
                var datValidityPeriod: Long

                try {
                    if (0 > dapsDriver.verifyToken(dat, fsm.remotePeerCertificate).also { datValidityPeriod = it }) {
                        LOG.warn("No valid remote DAT is available. Send IDSCP_CLOSE")
                        fsm.sendFromFSM(
                            Idscp2MessageHelper.createIdscpCloseMessage(
                                "No valid DAT",
                                CloseCause.NO_VALID_DAT
                            )
                        )
                        return@Transition FSM.FsmResult(
                            FSM.FsmResultCode.INVALID_DAT,
                            fsm.getState(FsmState.STATE_CLOSED)
                        )
                    }
                } catch (e: Exception) {
                    LOG.warn("DapsDriver has thrown Exception while validating remote DAT. Send IDSCP_CLOSE.", e)
                    fsm.sendFromFSM(
                        Idscp2MessageHelper.createIdscpCloseMessage(
                            "No valid DAT",
                            CloseCause.NO_VALID_DAT
                        )
                    )
                    return@Transition FSM.FsmResult(FSM.FsmResultCode.INVALID_DAT, fsm.getState(FsmState.STATE_CLOSED))
                }

                if (LOG.isTraceEnabled) {
                    LOG.trace("Remote DAT is valid. Set dat timeout")
                }
                fsm.setPeerDat(dat)
                datTimer.resetTimeout(datValidityPeriod * 1000)

                // start RA Verifier
                if (!fsm.restartRaVerifierDriver()) {
                    LOG.warn("Cannot run RA verifier, close idscp connection")
                    return@Transition FSM.FsmResult(FSM.FsmResultCode.RA_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }

                FSM.FsmResult(FSM.FsmResultCode.OK, fsm.getState(FsmState.STATE_WAIT_FOR_RA_VERIFIER))
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
                FSM.FsmResult(FSM.FsmResultCode.OK, fsm.getState(FsmState.STATE_WAIT_FOR_DAT_AND_RA))
            }
        )

        addTransition(
            IdscpMessage.IDSCPRERA_FIELD_NUMBER,
            Transition {
                if (LOG.isDebugEnabled) {
                    LOG.debug("Peer is requesting a re-attestation")
                }
                if (!fsm.restartRaProverDriver()) {
                    LOG.warn("Cannot run RA prover, close idscp connection")
                    return@Transition FSM.FsmResult(FSM.FsmResultCode.RA_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }
                FSM.FsmResult(FSM.FsmResultCode.OK, fsm.getState(FsmState.STATE_WAIT_FOR_DAT_AND_RA))
            }
        )

        addTransition(
            IdscpMessage.IDSCPACK_FIELD_NUMBER,
            Transition {
                fsm.recvAck(it.idscpMessage.idscpAck)
                FSM.FsmResult(FSM.FsmResultCode.OK, this)
            }
        )

        setNoTransitionHandler { event: Event? ->
            if (LOG.isTraceEnabled) {
                LOG.trace("No transition available for given event " + event.toString())
            }
            FSM.FsmResult(FSM.FsmResultCode.UNKNOWN_TRANSITION, this)
        }
    }
}
