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

import de.fhg.aisec.ids.idscp2.api.drivers.RaProverDriver
import de.fhg.aisec.ids.idscp2.api.drivers.RaVerifierDriver
import de.fhg.aisec.ids.idscp2.api.drivers.VerifiedDat
import de.fhg.aisec.ids.idscp2.messages.IDSCP2
import java.security.cert.X509Certificate

interface FSM {
    val bufferedIdscpMessage: IDSCP2.IdscpMessage?
    val raProverDriver: RaProverDriver<*>?
    val raVerifierDriver: RaVerifierDriver<*>?
    var ackFlag: Boolean
    val dynamicAttributeToken: ByteArray
    val remotePeerCertificate: X509Certificate
    val isFsmLocked: Boolean
    val isConnected: Boolean
    val remotePeer: String
    val localDat: ByteArray
    var peerDat: VerifiedDat

    fun notifyHandshakeCompleteLock()
    fun getState(state: FsmState): State
    fun sendFromFSM(message: IDSCP2.IdscpMessage): Boolean
    fun setBufferedIdscpData(message: IDSCP2.IdscpMessage)
    fun restartRaVerifierDriver(): Boolean
    fun restartRaProverDriver(): Boolean
    fun recvData(idscpData: IDSCP2.IdscpData)
    fun recvAck(idscpAck: IDSCP2.IdscpAck): Boolean
    fun getRaProverMechanism(localSupportedProver: Array<String>, remoteExpectedVerifier: Array<String>): String?
    fun getRaVerifierMechanism(localExpectedVerifier: Array<String>, remoteSupportedProver: Array<String>): String?
    fun setRaMechanisms(proverMechanism: String, verifierMechanism: String)
    fun stopRaVerifierDriver()
    fun shutdownFsm()
    fun closeConnection(): FsmResultCode
    fun send(msg: ByteArray?): FsmResultCode
    fun repeatRa(): FsmResultCode
}
