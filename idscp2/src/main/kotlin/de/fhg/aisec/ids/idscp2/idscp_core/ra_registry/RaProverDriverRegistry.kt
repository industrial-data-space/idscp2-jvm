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
package de.fhg.aisec.ids.idscp2.idscp_core.ra_registry

import de.fhg.aisec.ids.idscp2.idscp_core.drivers.RaProverDriver
import de.fhg.aisec.ids.idscp2.idscp_core.fsm.fsmListeners.RaProverFsmListener
import org.slf4j.LoggerFactory
import java.util.concurrent.ConcurrentHashMap

/**
 * A RA Prover Driver Registry
 * The User can register Driver implementation instances and its configurations to the registry
 *
 *
 * The Idscp2 protocol will select during the idscp handshake a RA Prover mechanism and will
 * check for this RaProver in this registry
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
object RaProverDriverRegistry {
    private val LOG by lazy { LoggerFactory.getLogger(RaProverDriverRegistry::class.java) }

    /**
     * An inner static wrapper class, that wraps driver config and driver class
     */
    private class DriverWrapper<PC>(
        val driverFactory: (RaProverFsmListener) -> RaProverDriver<PC>,
        val driverConfig: PC?
    ) {
        fun getInstance(listener: RaProverFsmListener) = driverFactory.invoke(listener).also { d ->
            driverConfig?.let { d.setConfig(it) }
        }
    }

    private val drivers = ConcurrentHashMap<String, DriverWrapper<*>>()

    /**
     * Register RA Prover driver and an optional configuration in the registry
     */
    fun <PC> registerDriver(
        instance: String,
        driverFactory: (RaProverFsmListener) -> RaProverDriver<PC>,
        driverConfig: PC?
    ) {
        if (LOG.isDebugEnabled) {
            LOG.debug("Register '{}' driver to RA prover registry", instance)
        }
        drivers[instance] = DriverWrapper(driverFactory, driverConfig)
    }

    /**
     * Unregister the driver from the registry
     */
    fun unregisterDriver(instance: String) {
        if (LOG.isDebugEnabled) {
            LOG.debug("Unregister '{}' driver from RA prover registry", instance)
        }
        drivers.remove(instance)
    }

    /**
     * To start a RA Prover from the finite state machine
     *
     * First we check if the registry contains the RaProver instance, then we create a new
     * RaProverDriver from the driver wrapper that holds the corresponding RaProverDriver class.
     *
     * The finite state machine is registered as the communication partner for the RaProver.
     * The RaProver will be initialized with a configuration, if present. Then it is started.
     */
    fun startRaProverDriver(instance: String, listener: RaProverFsmListener): RaProverDriver<*>? {
        return drivers[instance]?.let { driverWrapper ->
            return try {
                driverWrapper.getInstance(listener).also { it.start() }
            } catch (e: Exception) {
                LOG.error("Error during RA prover start", e)
                null
            }
        }
    }
}
