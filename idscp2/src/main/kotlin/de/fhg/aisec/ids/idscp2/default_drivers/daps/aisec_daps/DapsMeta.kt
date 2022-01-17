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
