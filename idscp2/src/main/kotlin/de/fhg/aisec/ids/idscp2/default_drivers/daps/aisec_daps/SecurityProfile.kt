package de.fhg.aisec.ids.idscp2.default_drivers.daps.aisec_daps

enum class SecurityProfile {
    // we use enum comparison, so ensure that INVALID option is the worst and TRUSTED_PLUS is the best
    INVALID,
    BASE,
    TRUSTED,
    TRUSTED_PLUS;

    companion object {
        const val CONNECTOR_SECURITY_PROFILE_BASE = "idsc:BASE_CONNECTOR_SECURITY_PROFILE"
        const val CONNECTOR_SECURITY_PROFILE_TRUSTED = "idsc:TRUSTED_CONNECTOR_SECURITY_PROFILE"
        const val CONNECTOR_SECURITY_PROFILE_TRUSTED_PLUS = "idsc:TRUSTED_CONNECTOR_PLUS_SECURITY_PROFILE"

        fun fromString(s: String) : SecurityProfile {
            return when (s) {
                CONNECTOR_SECURITY_PROFILE_BASE -> BASE
                CONNECTOR_SECURITY_PROFILE_TRUSTED -> TRUSTED
                CONNECTOR_SECURITY_PROFILE_TRUSTED_PLUS -> TRUSTED_PLUS
                else -> INVALID
            }
        }
    }
}