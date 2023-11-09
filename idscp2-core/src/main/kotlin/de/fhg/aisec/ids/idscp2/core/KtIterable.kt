/*-
 * ========================LICENSE_START=================================
 * idscp2-core
 * %%
 * Copyright (C) 2023 Fraunhofer AISEC
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
package de.fhg.aisec.ids.idscp2.core

import org.slf4j.Logger

/**
 * This extension features an error-resilient iteration.
 * Errors are logged via the given slf4j Logger object.
 */
inline fun <T> Iterable<T>.forEachResilient(logger: Logger, action: (T) -> Unit) {
    for (element in this) {
        try {
            action(element)
        } catch (t: Throwable) {
            logger.error("Error during iteration", t)
        }
    }
}
