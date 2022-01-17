/*-
 * ========================LICENSE_START=================================
 * idscp2
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
package de.fhg.aisec.ids.idscp2.default_drivers.daps.aisec_daps

import de.fhg.aisec.ids.idscp2.idscp_core.error.DatException
import org.json.JSONObject
import java.net.URI

data class DapsMeta(val issuer: String, val jwksUri: String, val tokenEndpoint: String) {
    companion object {
        fun fromDapsUrl(url: String): DapsMeta {
            val dapsUri = URI(url)
            return DapsMeta(
                "${dapsUri.scheme}://${dapsUri.host}",
                "$url/.well-known/jwks.json",
                "$url/token"
            )
        }
        fun fromJson(jsonString: String): DapsMeta {
            val json = JSONObject(jsonString)
            return DapsMeta(
                json.getString("issuer")
                    ?: throw DatException("\"issuer\" not found in DAPS meta JSON"),
                json.getString("jwks_uri")
                    ?: throw DatException("\"jwks_uri\" not found in DAPS meta JSON"),
                json.getString("token_endpoint")
                    ?: throw DatException("\"token_endpoint\" not found in DAPS meta JSON")
            )
        }
    }
}
