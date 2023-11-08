/*-
 * ========================LICENSE_START=================================
 * idscp2-api
 * %%
 * Copyright (C) 2022 Fraunhofer AISEC
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
package de.fhg.aisec.ids.idscp2.keystores

import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.slf4j.LoggerFactory
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.IOException
import java.nio.file.Path
import java.security.KeyStore
import kotlin.io.path.readBytes

object KeyStoreUtil {
    private const val JKS_MAGIC_NUMBER: Int = (0xFEEDFEED).toInt()
    private val LOG = LoggerFactory.getLogger(KeyStoreUtil::class.java)

    /**
     * Detect JKS format or PKCS#12 format from KeyStore bytes.
     * Inspired by KeyStoreExplorer's org.kse.crypto.filetype.CryptoFileUtil.detectKeyStoreType().
     * @param data The bytes of a KeyStore file
     * @return The KeyStore type, if supported
     */
    private fun getKeyStoreType(data: ByteArray): String {
        DataInputStream(ByteArrayInputStream(data)).use { dis ->
            // If there are not > 4 bytes available, it is not a KeyStore
            if (dis.available() < 4) {
                throw RuntimeException("KeyStore is too small to be an actual KeyStore!")
            }

            // Check for JKS
            if (dis.readInt() == JKS_MAGIC_NUMBER) {
                return "JKS"
            }
        }

        /*
         * Check for PKCS#12. Expected ASN.1 format:
         *
         * PFX ::= ASN1Sequence {
         * 		version ASN1Integer {v3(3)}(v3,...),
         * 		authSafe ContentInfo,
         * 		macData MacData OPTIONAL
         * }
         */
        val pfx = try {
            ASN1Primitive.fromByteArray(data)
        } catch (e: IOException) {
            throw RuntimeException("KeyStore not supported, could not detect JKS magic bytes or parse as ASN.1.")
        }

        // ASN.1 primitive has to be a sequence of size 2 or 3
        if (pfx is ASN1Sequence && pfx.size() in 2..3) {
            // First object of the sequence has to be an ASN.1 integer with value 3
            pfx.getObjectAt(0).let {
                if (it is ASN1Integer && it.value.toInt() == 3) {
                    return "PKCS12"
                }
            }
        }

        throw RuntimeException(
            "KeyStore not supported, could not detect JKS magic bytes or valid PKCS#12 structure in parsed ASN.1"
        )
    }

    /**
     * Load a KeyStore of a supported type (JKS or PKCS#12).
     * Try to fall back to KeyStore.getDefaultType() if detection fails.
     */
    fun loadKeyStore(keyStorePath: Path, keyStorePassword: CharArray): KeyStore {
        val keyStoreBytes = keyStorePath.readBytes()
        val ks = try {
            val type = getKeyStoreType(keyStoreBytes)
            KeyStore.getInstance(type)
        } catch (e: RuntimeException) {
            val defaultType = KeyStore.getDefaultType()
            LOG.warn(
                "Could not detect KeyStore type, PKCS#12 or JKS expected. Trying default type \"$defaultType\".",
                e
            )
            KeyStore.getInstance(defaultType)
        }
        return ks.apply {
            if (LOG.isTraceEnabled) {
                LOG.trace("Try loading key store: {}", keyStorePath)
            }
            load(ByteArrayInputStream(keyStoreBytes), keyStorePassword)
        }
    }
}
