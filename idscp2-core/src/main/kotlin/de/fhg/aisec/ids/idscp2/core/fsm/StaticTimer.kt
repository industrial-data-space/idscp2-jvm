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

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * A StaticTimer class that provides an API to the FSM to start and cancel timeout threads
 * with a fixed timeout delay (in ms)
 * The timer ensures that no canceled timer is able to trigger a timeout transitions
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class StaticTimer internal constructor(
    private val fsmIsBusy: ReentrantLock,
    private val timeoutHandler: Runnable,
    val delay: Long
) {
    private var job: Job? = null

    fun resetTimeout() {
        cancelTimeout()
        start()
    }

    /**
     * Start a timer thread that triggers the timeout handler routine after the static delay
     */
    @Synchronized
    fun start() {
        job = scope.launch {
            delay(delay)
            fsmIsBusy.withLock {
                timeoutHandler.run()
            }
        }
    }

    /**
     * Cancel the current timer thread
     */
    @Synchronized
    fun cancelTimeout() {
        job?.cancel()
    }

    companion object {
        private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    }
}
