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
package de.fhg.aisec.ids.idscp2.default_drivers.secure_channel.tlsv1_3.client

import java.io.DataInputStream
import java.io.EOFException
import java.io.InputStream
import java.net.SocketTimeoutException

/**
 * A simple Listener thread that listens to an input stream and notifies a listeners
 * when new data has been received
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class InputListenerThread(inputStream: InputStream, private var listener: DataAvailableListener) : Thread() {
    private val dataInputStream: DataInputStream = DataInputStream(inputStream)

    @Volatile
    private var running = true

    /*
     * Run the input listener thread that reads from wire and provides data to upper layer
     */
    override fun run() {
        var buf: ByteArray
        while (running) {
            try {
                // first read the length
                val len = dataInputStream.readInt()
                buf = ByteArray(len)
                // then read the data
                dataInputStream.readFully(buf, 0, len)
                // provide to listener
                listener.onMessage(buf)
            } catch (ignore: SocketTimeoutException) {
                // timeout to catch safeStop() call
            } catch (e: EOFException) {
                listener.onClose()
                running = false
            } catch (e: Exception) {
                listener.onError(e)
                running = false
            }
        }
        try {
            dataInputStream.close()
        } catch (ignore: Exception) {}
    }

    fun safeStop() {
        running = false
    }
}
