/*-
 * ========================LICENSE_START=================================
 * camel-idscp2
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
@file:Suppress("DEPRECATION")

package de.fhg.aisec.ids.camel.idscp2.client

import de.fhg.aisec.ids.idscp2.default_drivers.remote_attestation.dummy.RaProverDummy
import de.fhg.aisec.ids.idscp2.default_drivers.remote_attestation.dummy.RaProverDummy2
import de.fhg.aisec.ids.idscp2.default_drivers.remote_attestation.dummy.RaVerifierDummy
import de.fhg.aisec.ids.idscp2.default_drivers.remote_attestation.dummy.RaVerifierDummy2
import de.fhg.aisec.ids.idscp2.idscp_core.ra_registry.RaProverDriverRegistry
import de.fhg.aisec.ids.idscp2.idscp_core.ra_registry.RaVerifierDriverRegistry
import org.apache.camel.Endpoint
import org.apache.camel.spi.annotations.Component
import org.apache.camel.support.DefaultComponent

@Component("idscp2client")
class Idscp2ClientComponent : DefaultComponent() {

    init {
        RaProverDriverRegistry.registerDriver(
            RaProverDummy.RA_PROVER_DUMMY_ID,
            ::RaProverDummy,
            null
        )
        RaProverDriverRegistry.registerDriver(
            RaProverDummy2.RA_PROVER_DUMMY2_ID,
            ::RaProverDummy2,
            null
        )
        RaVerifierDriverRegistry.registerDriver(
            RaVerifierDummy.RA_VERIFIER_DUMMY_ID,
            ::RaVerifierDummy,
            null
        )
        RaVerifierDriverRegistry.registerDriver(
            RaVerifierDummy2.RA_VERIFIER_DUMMY2_ID,
            ::RaVerifierDummy2,
            null
        )
    }

    override fun createEndpoint(uri: String, remaining: String, parameters: Map<String, Any>): Endpoint {
        val endpoint: Endpoint = Idscp2ClientEndpoint(uri, remaining, this)
        setProperties(endpoint, parameters)
        return endpoint
    }
}
