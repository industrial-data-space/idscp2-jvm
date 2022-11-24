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

import de.fhg.aisec.ids.idscp2.core.api.configuration.AttestationConfig
import de.fhg.aisec.ids.idscp2.core.drivers.DapsDriver
import de.fhg.aisec.ids.idscp2.core.fsm.FSM.FsmState
import de.fhg.aisec.ids.idscp2.core.messages.Idscp2MessageHelper
import de.fhg.aisec.ids.idscp2.messages.IDSCP2.IdscpClose.CloseCause
import de.fhg.aisec.ids.idscp2.messages.IDSCP2.IdscpMessage
import org.slf4j.LoggerFactory

/**
 * The Wait_For_Hello State of the FSM of the IDSCP2 protocol.
 * Waits for the Idscp2 Hellp Message that contains the protocol version, the supported and
 * expected remote attestation cipher suites and the dynamic attribute token (DAT) of the peer.
 *
 *
 * Goes into the WAIT_FOR_RA State when valid RA mechanisms were found and the DAT is valid
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class StateWaitForHello(
    fsm: FSM,
    private val handshakeTimer: StaticTimer,
    datTimer: DynamicTimer,
    dapsDriver: DapsDriver,
    attestationConfig: AttestationConfig
) : State() {
    override fun runEntryCode(fsm: FSM) {
        if (LOG.isTraceEnabled) {
            LOG.trace("Switched to state STATE_WAIT_FOR_HELLO")
            LOG.trace("Set handshake timeout to ${handshakeTimer.delay} ms.")
        }
        handshakeTimer.resetTimeout()
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(StateWaitForHello::class.java)
    }

    init {

        /*---------------------------------------------------
         * STATE_WAIT_FOR_HELLO - Transition Description
         * ---------------------------------------------------
         * onICM: error --> {} ---> STATE_CLOSED
         * onICM: stop --> {send IDSCP_CLOSE} ---> STATE_CLOSED
         * onICM: timeout --> {send IDSCP_CLOSE} ---> STATE_CLOSED
         * onMessage: IDSCP_CLOSE---> {} ---> STATE_CLOSED
         * onMessage: IDSCP_HELLO (no ra match) ---> {send IDSCP_CLOSE} ---> STATE_CLOSED
         * onMessage: IDSCP_HELLO (invalid DAT) ---> {send IDSCP_CLOSE} ---> STATE_CLOSED
         * onMessage: IDSCP_HELLO (SUCCESS) ---> {verify DAT, match RA, set DAT Timeout, start RA P&V,
         *                                        set handshake_timeout} ---> STATE_WAIT_FOR_RA
         * ALL_OTHER_MESSAGES ---> {} ---> STATE_WAIT_FOR_HELLO
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
                    LOG.trace("Received stop signal from user. Send IDSCP_CLOSE")
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
                if (LOG.isTraceEnabled) {
                    LOG.trace("Received SEND signal from user, but FSM is not connected yet")
                }
                FSM.FsmResult(FSM.FsmResultCode.NOT_CONNECTED, this)
            }
        )

        addTransition(
            InternalControlMessage.REPEAT_RA.value,
            Transition {
                // nothing to to, result should be okay since RA will be done in the next
                // state for the first time
                if (LOG.isTraceEnabled) {
                    LOG.trace("Received REPEAT_RA signal from user")
                }
                FSM.FsmResult(FSM.FsmResultCode.OK, this)
            }
        )

        addTransition(
            InternalControlMessage.TIMEOUT.value,
            Transition {
                LOG.warn("STATE_WAIT_FOR_HELLO timeout. Send IDSCP_CLOSE")
                fsm.sendFromFSM(
                    Idscp2MessageHelper.createIdscpCloseMessage(
                        "Handshake Timeout",
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
                    LOG.trace("Received IDSCP_CLOSE. Close connection")
                }
                FSM.FsmResult(FSM.FsmResultCode.OK, fsm.getState(FsmState.STATE_CLOSED))
            }
        )

        addTransition(
            IdscpMessage.IDSCPHELLO_FIELD_NUMBER,
            Transition { event: Event ->
                handshakeTimer.cancelTimeout()

                val idscpHello = event.idscpMessage.idscpHello
                if (LOG.isTraceEnabled) {
                    LOG.trace("Received IDSCP_HELLO")
                }

                if (LOG.isTraceEnabled) {
                    LOG.trace("Calculate RA mechanisms")
                }
                val proverMechanism = fsm.getRaProverMechanism(
                    attestationConfig.supportedAttestationSuite,
                    idscpHello.expectedRaSuiteList.toTypedArray()
                )

                if (proverMechanism == null) {
                    LOG.warn("No match for RA prover mechanism")
                    return@Transition FSM.FsmResult(
                        FSM.FsmResultCode.RA_NEGOTIATION_ERROR,
                        fsm.getState(FsmState.STATE_CLOSED)
                    )
                }

                val verifierMechanism = fsm.getRaVerifierMechanism(
                    attestationConfig.expectedAttestationSuite,
                    idscpHello.supportedRaSuiteList.toTypedArray()
                )

                if (verifierMechanism == null) {
                    LOG.warn("No match for RA verifier mechanism")
                    return@Transition FSM.FsmResult(
                        FSM.FsmResultCode.RA_NEGOTIATION_ERROR,
                        fsm.getState(FsmState.STATE_CLOSED)
                    )
                }

                if (LOG.isTraceEnabled) {
                    LOG.trace("Verify received DAT")
                }
                // check if Dat is available and verify dat
                var datValidityPeriod: Long

                if (!idscpHello.hasDynamicAttributeToken()) {
                    LOG.warn("No remote DAT is available. Send IDSCP_CLOSE")
                    fsm.sendFromFSM(
                        Idscp2MessageHelper.createIdscpCloseMessage(
                            "No valid DAT",
                            CloseCause.NO_VALID_DAT
                        )
                    )
                    return@Transition FSM.FsmResult(FSM.FsmResultCode.MISSING_DAT, fsm.getState(FsmState.STATE_CLOSED))
                }

                val remoteDat = idscpHello.dynamicAttributeToken.token.toByteArray()
                try {
                    if (0 > dapsDriver.verifyToken(
                            remoteDat,
                            fsm.remotePeerCertificate
                        ).also { datValidityPeriod = it }
                    ) {
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
                    LOG.warn("DapsDriver throws Exception while validating remote DAT. Send IDSCP_CLOSE.", e)
                    fsm.sendFromFSM(
                        Idscp2MessageHelper.createIdscpCloseMessage(
                            "No valid DAT",
                            CloseCause.NO_VALID_DAT
                        )
                    )
                    return@Transition FSM.FsmResult(FSM.FsmResultCode.INVALID_DAT, fsm.getState(FsmState.STATE_CLOSED))
                }

                if (LOG.isTraceEnabled) {
                    LOG.trace("Remote DAT is valid. Set dat timeout to its validity period")
                }
                fsm.setPeerDat(remoteDat)
                datTimer.resetTimeout(datValidityPeriod * 1000)
                fsm.setRaMechanisms(proverMechanism, verifierMechanism)

                if (LOG.isTraceEnabled) {
                    LOG.debug("Start RA Prover and Verifier")
                }
                if (!fsm.restartRaVerifierDriver()) {
                    LOG.warn("Cannot run RA verifier, close idscp connection")
                    return@Transition FSM.FsmResult(FSM.FsmResultCode.RA_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }
                if (!fsm.restartRaProverDriver()) {
                    LOG.warn("Cannot run RA prover, close idscp connection")
                    return@Transition FSM.FsmResult(FSM.FsmResultCode.RA_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }

                FSM.FsmResult(FSM.FsmResultCode.OK, fsm.getState(FsmState.STATE_WAIT_FOR_RA))
            }
        )

        setNoTransitionHandler {
            if (LOG.isTraceEnabled) {
                LOG.trace("No transition available for given event $it")
                LOG.trace("Stay in state STATE_WAIT_FOR_HELLO")
            }
            FSM.FsmResult(FSM.FsmResultCode.UNKNOWN_TRANSITION, this)
        }
    }
}
