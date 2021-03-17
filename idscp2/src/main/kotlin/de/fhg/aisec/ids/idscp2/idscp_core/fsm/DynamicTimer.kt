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

import java.util.concurrent.locks.ReentrantLock

/**
 * A DynamicTimer class that provides an API to the FSM to start and cancel timeout threads
 * without a fixed timeout delay (in ms)
 * The timer ensures that no canceled timer is able to trigger a timeout transitions
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class DynamicTimer internal constructor(private val fsmIsBusy: ReentrantLock, private val timeoutHandler: Runnable) {
    private var thread: TimerThread? = null
    private val mutex = ReentrantLock(true)
    fun resetTimeout(delay: Long) {
        cancelTimeout()
        start(delay)
    }

    /*
     * Start a timer thread that triggers the timeout handler routine after a given timout delay
     */
    fun start(delay: Long) {
        mutex.lock()
        thread = TimerThread(delay, timeoutHandler, fsmIsBusy).also { it.start() }
        mutex.unlock()
    }

    /*
     * Cancel the current timer thread
     */
    fun cancelTimeout() {
        mutex.lock()
        thread?.safeStop()
        thread = null
        mutex.unlock()
    }
}
