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
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.GregorianCalendar
import javax.xml.datatype.DatatypeFactory
import javax.xml.datatype.XMLGregorianCalendar

object Utils {
    val SERIALIZER: Serializer by lazy { Serializer() }

    lateinit var maintainerUrlProducer: () -> URI
    lateinit var connectorUrlProducer: () -> URI
    lateinit var infomodelVersion: String
    var dapsUrlProducer: () -> String = { Constants.DEFAULT_DAPS_URL }

    fun createGregorianCalendarTimestamp(timeInput: Long): XMLGregorianCalendar? {
        return DatatypeFactory.newInstance().newXMLGregorianCalendar(
            GregorianCalendar().apply { timeInMillis = timeInput }
        )
    }

    fun finalizeMessage(builder: Any, connection: Idscp2Connection): Message {
        try {
            builder::class.java.apply {
                getMethod("_securityToken_", DynamicAttributeToken::class.java)
                    .invoke(
                        builder,
                        DynamicAttributeTokenBuilder()
                            ._tokenFormat_(TokenFormat.JWT)
                            ._tokenValue_(String(connection.localDynamicAttributeToken, StandardCharsets.UTF_8))
                            .build()
                    )
                getMethod("_senderAgent_", URI::class.java).invoke(builder, maintainerUrlProducer())
                getMethod("_issuerConnector_", URI::class.java).invoke(builder, connectorUrlProducer())
                getMethod("_issued_", XMLGregorianCalendar::class.java)
                    .invoke(builder, createGregorianCalendarTimestamp(System.currentTimeMillis()))
                getMethod("_modelVersion_", String::class.java).invoke(builder, infomodelVersion)
                val message = getMethod("build").invoke(builder)
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
        }
    }
}
