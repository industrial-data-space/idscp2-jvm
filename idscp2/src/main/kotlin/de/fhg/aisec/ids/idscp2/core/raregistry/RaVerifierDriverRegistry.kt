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
package de.fhg.aisec.ids.idscp2.core.raregistry

import de.fhg.aisec.ids.idscp2.core.drivers.RaVerifierDriver
import de.fhg.aisec.ids.idscp2.core.fsm.fsmListeners.RaVerifierFsmListener
import org.slf4j.LoggerFactory
import java.util.concurrent.ConcurrentHashMap

/**
 * A Ra Verifier Driver Registry
 * The User can register Driver implementation instances and its configurations to the registry
 *
 *
 * The Idscp2 protocol will select during the idscp handshake a RA Verifier mechanism and will
 * check for this RaVerifier in this registry
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
object RaVerifierDriverRegistry {
    private val LOG by lazy { LoggerFactory.getLogger(RaVerifierDriverRegistry::class.java) }

    /**
     * An inner static wrapper class, that wraps driver config and driver class
     */
    private class DriverWrapper<VC>(
        val driverFactory: (RaVerifierFsmListener) -> RaVerifierDriver<VC>,
        val driverConfig: VC?
    ) {
        fun getInstance(listener: RaVerifierFsmListener) = driverFactory.invoke(listener).also { d ->
            driverConfig?.let { d.setConfig(it) }
        }
    }

    private val drivers = ConcurrentHashMap<String, DriverWrapper<*>>()

    /**
     * Register RA Verifier driver and an optional configuration in the registry
     */
    fun <VC> registerDriver(
        instance: String,
        driverFactory: (RaVerifierFsmListener) -> RaVerifierDriver<VC>,
        driverConfig: VC?
    ) {
        if (LOG.isDebugEnabled) {
            LOG.debug("Register '{}' driver to RA verifier registry", instance)
        }
        drivers[instance] = DriverWrapper(driverFactory, driverConfig)
    }

    /**
     * Unregister the driver from the registry
     */
    fun unregisterDriver(instance: String) {
        if (LOG.isDebugEnabled) {
            LOG.debug("Register '{}' driver from RA verifier registry", instance)
        }
        drivers.remove(instance)
    }

    /**
     * To start a RA Verifier from the finite state machine
     *
     * First we check if the registry contains the RaVerifier instance, then we create a new
     * RaVerifierDriver from the driver wrapper that holds the corresponding
     * RaVerifierDriver class.
     *
     * The finite state machine is registered as the communication partner for the RaVerifier.
     * The RaVerifier will be initialized with a configuration, if present. Then it is started.
     */
    fun startRaVerifierDriver(mechanism: String?, listener: RaVerifierFsmListener): RaVerifierDriver<*>? {
        return drivers[mechanism]?.let { driverWrapper ->
            return try {
                driverWrapper.getInstance(listener).also { it.start() }
            } catch (e: Exception) {
                LOG.error("Error during RA verifier start", e)
                null
            }
        }
    }
}
