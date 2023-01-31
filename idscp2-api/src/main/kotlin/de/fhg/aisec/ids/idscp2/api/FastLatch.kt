/*-
 * ========================LICENSE_START=================================
 * idscp2-api
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
package de.fhg.aisec.ids.idscp2.api

import org.slf4j.LoggerFactory

/**
 * This latch implementation uses double-checked-locking, a concept that is mostly broken.
 * However, double-checked locking **does** work for primitives that are atomic w.r.t. the memory model,
 * see https://www.cs.umd.edu/~pugh/java/memoryModel/DoubleCheckedLocking.html
 * It is assumed that the JVM implementation always handles byte vars atomically,
 * otherwise the correctness of this code may be broken!
 *
 * @author Michael Lux (michael.lux@aisec.fraunhofer.de)
 */
@Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
class FastLatch {
    private var locked: Byte = 1

    /**
     * Wait for this latch to be unlocked.
     */
    fun await() {
        // Check locked flag without synchronization, such that method returns immediately
        // without synchronization overhead if unlocked.
        while (locked.toInt() != 0) {
            synchronized(this) {
                // Check the locked flag again to prevent eternal waiting if notifyAll() has been called
                // before this critical section.
                if (locked.toInt() != 0) {
                    try {
                        @Suppress("BlockingMethodInNonBlockingContext")
                        (this as Object).wait()
                    } catch (ie: InterruptedException) {
                        LOG.warn("Ignored InterruptException, awaiting unlock...", ie)
                    }
                }
            }
        }
    }

    /**
     * Unlocks this latch instance.
     */
    fun unlock() {
        synchronized(this) {
            locked = 0
            (this as Object).notifyAll()
        }
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(FastLatch::class.java)
    }
}
