package de.fhg.aisec.ids.idscp2.core.fsm

import de.fhg.aisec.ids.idscp2.api.fsm.State
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory

open class RaState : State() {
    fun runAsync(runnable: Runnable) {
        ioScope.launch {
            runnable.run()
        }
    }
    companion object {
        private val LOG = LoggerFactory.getLogger(RaState::class.java)
        private val ioScope = CoroutineScope(Dispatchers.IO + CoroutineExceptionHandler { _, throwable ->
            LOG.error("Error in async RA code", throwable)
        })
    }
}
