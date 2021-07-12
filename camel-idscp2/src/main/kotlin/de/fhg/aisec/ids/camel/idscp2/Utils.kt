/*-
 * ========================LICENSE_START=================================
 * camel-idscp2
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
package de.fhg.aisec.ids.camel.idscp2

import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_connection.Idscp2Connection
import de.fraunhofer.iais.eis.DynamicAttributeToken
import de.fraunhofer.iais.eis.DynamicAttributeTokenBuilder
import de.fraunhofer.iais.eis.Message
import de.fraunhofer.iais.eis.TokenFormat
import de.fraunhofer.iais.eis.ids.jsonld.Serializer
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.GregorianCalendar
import javax.xml.datatype.DatatypeFactory
import javax.xml.datatype.XMLGregorianCalendar

object Utils {
    val SERIALIZER: Serializer by lazy { Serializer() }
    val LOG: Logger = LoggerFactory.getLogger(Utils::class.java)

    lateinit var maintainerUrlProducer: () -> URI
    lateinit var connectorUrlProducer: () -> URI
    lateinit var infomodelVersion: String
    var dapsUrlProducer: () -> String = { Constants.DEFAULT_DAPS_URL }

    fun createGregorianCalendarTimestamp(timeInput: Long): XMLGregorianCalendar? {
        return DatatypeFactory.newInstance().newXMLGregorianCalendar(
            GregorianCalendar().apply { timeInMillis = timeInput }
        )
    }

    fun finalizeMessage(messageOrBuilder: Any, connection: Idscp2Connection): Message {
        if (messageOrBuilder is Message) {
            if (LOG.isDebugEnabled) {
                LOG.debug(
                    "Object passed to finalizeMessage is already a Message, " +
                        "no methods will be called."
                )
            }
            return messageOrBuilder
        }
        try {
            if (LOG.isDebugEnabled) {
                LOG.debug("Finalizing IDS MessageBuilder object...")
            }
            messageOrBuilder::class.java.apply {
                getMethod("_securityToken_", DynamicAttributeToken::class.java)
                    .invoke(
                        messageOrBuilder,
                        DynamicAttributeTokenBuilder()
                            ._tokenFormat_(TokenFormat.JWT)
                            ._tokenValue_(String(connection.localDynamicAttributeToken, StandardCharsets.UTF_8))
                            .build()
                    )
                getMethod("_senderAgent_", URI::class.java).invoke(messageOrBuilder, maintainerUrlProducer())
                getMethod("_issuerConnector_", URI::class.java).invoke(messageOrBuilder, connectorUrlProducer())
                getMethod("_issued_", XMLGregorianCalendar::class.java)
                    .invoke(messageOrBuilder, createGregorianCalendarTimestamp(System.currentTimeMillis()))
                getMethod("_modelVersion_", String::class.java).invoke(messageOrBuilder, infomodelVersion)
                val message = getMethod("build").invoke(messageOrBuilder)
                if (message !is Message) {
                    throw CamelIdscp2Exception(
                        "InfoModel message build failed! build() did not return a Message object!"
                    )
                }
                return message
            }
        } catch (upa: UninitializedPropertyAccessException) {
            throw CamelIdscp2Exception(
                "At least one property of de.fhg.aisec.ids.camel.idscp2.Utils has not been " +
                    "properly initialized. This is a mandatory requirement for initialization " +
                    "of IDSCP Messages within the IDSCP2 Camel Adapter!",
                upa
            )
        } catch (t: Throwable) {
            throw CamelIdscp2Exception(
                "Failed to finalize IDS MessageBuilder, " +
                    "the object passed as IDSCP2 header must be an IDS Message or an IDS MessageBuilder.",
                t
            )
        }
    }
}
