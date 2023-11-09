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
