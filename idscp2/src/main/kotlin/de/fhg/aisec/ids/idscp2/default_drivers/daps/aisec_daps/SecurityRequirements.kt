package de.fhg.aisec.ids.idscp2.default_drivers.daps.aisec_daps

/**
 * A Security-Requirements class using Builder pattern to store the connectors expected
 * security attributes e.g. Audit Logging
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class SecurityRequirements {
    lateinit var requiredSecurityLevel: SecurityProfile
        private set

    class Builder {
        private val requirements = SecurityRequirements()
        fun setRequiredSecurityLevel(securityProfile: SecurityProfile): Builder {
            requirements.requiredSecurityLevel = securityProfile
            return this
        }

        fun build(): SecurityRequirements {
            return requirements
        }
    }
}