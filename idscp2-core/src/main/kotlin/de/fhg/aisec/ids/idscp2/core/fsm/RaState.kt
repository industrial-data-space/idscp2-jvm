package de.fhg.aisec.ids.idscp2.core.fsm

import de.fhg.aisec.ids.idscp2.api.fsm.State
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

open class RaState : State() {
    fun runAsync(runnable: Runnable) {
        ioScope.launch {
            runnable.run()
        }
    }
    companion object {
        private val ioScope = CoroutineScope(Dispatchers.IO)
    }
}
