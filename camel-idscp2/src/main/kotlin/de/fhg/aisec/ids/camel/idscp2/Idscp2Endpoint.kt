package de.fhg.aisec.ids.camel.idscp2

import de.fhg.aisec.ids.idscp2.api.configuration.AttestationConfig
import de.fhg.aisec.ids.idscp2.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.daps.aisecdaps.AisecDapsDriver
import de.fhg.aisec.ids.idscp2.daps.aisecdaps.AisecDapsDriverConfig
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.NativeTlsConfiguration
import org.apache.camel.support.jsse.SSLContextParameters
import java.nio.file.Paths
import java.util.regex.Pattern

interface Idscp2Endpoint {

    val supportedRaSuites: String
    val expectedRaSuites: String
    val dapsRaTimeoutDelay: Long
    val remaining: String
    val transportSslContextParameters: SSLContextParameters?
    val dapsSslContextParameters: SSLContextParameters?
    val sslContextParameters: SSLContextParameters?

    fun Idscp2Endpoint.createCommonEndpointConfigurations(): Pair<Idscp2Configuration, NativeTlsConfiguration.Builder> {
        val remainingMatcher = URI_REGEX.matcher(remaining)
        require(remainingMatcher.matches()) { "$remaining is not a valid URI remainder, must be \"host:port\"." }
        val matchResult = remainingMatcher.toMatchResult()
        val host = matchResult.group(1)
        val port = matchResult.group(2)?.toInt() ?: NativeTlsConfiguration.DEFAULT_SERVER_PORT

        // create attestation config
        val localAttestationConfig = AttestationConfig.Builder()
            .setSupportedRaSuite(supportedRaSuites.split('|').toTypedArray())
            .setExpectedRaSuite(expectedRaSuites.split('|').toTypedArray())
            .setRaTimeoutDelay(dapsRaTimeoutDelay)
            .build()

        // create daps config
        val dapsDriverConfigBuilder = AisecDapsDriverConfig.Builder()
            .setDapsUrl(Utils.dapsUrlProducer())

        val secureChannelConfigBuilder = NativeTlsConfiguration.Builder()
            .setHost(host)
            .setServerPort(port)

        (transportSslContextParameters ?: sslContextParameters)?.let {
            applySslContextParameters(secureChannelConfigBuilder, it)
        }

        (dapsSslContextParameters ?: sslContextParameters)?.let {
            applySslContextParameters(dapsDriverConfigBuilder, it)
        }

        // create idscp config
        val serverConfiguration = Idscp2Configuration.Builder()
            .setAttestationConfig(localAttestationConfig)
            .setDapsDriver(AisecDapsDriver(dapsDriverConfigBuilder.build()))
            .build()

        return Pair(serverConfiguration, secureChannelConfigBuilder)
    }

    companion object {
        private val URI_REGEX = Pattern.compile("(.*?)(?::(\\d+))?/?$")

        fun applySslContextParameters(
            builder: NativeTlsConfiguration.Builder,
            sslContextParameters: SSLContextParameters
        ): NativeTlsConfiguration.Builder {
            return builder.apply {
                sslContextParameters.let {
                    setKeyPassword(
                        it.keyManagers?.keyPassword?.toCharArray()
                            ?: "password".toCharArray()
                    )
                    it.keyManagers?.keyStore?.resource?.let { setKeyStorePath(Paths.get(it)) }
                    it.keyManagers?.keyStore?.type?.let { setKeyStoreKeyType(it) }
                    setKeyStorePassword(
                        it.keyManagers?.keyStore?.password?.toCharArray()
                            ?: "password".toCharArray()
                    )
                    it.trustManagers?.trustManager?.let { setTrustManager(it) }
                    it.trustManagers?.keyStore?.resource?.let { setTrustStorePath(Paths.get(it)) }
                    setTrustStorePassword(
                        it.trustManagers?.keyStore?.password?.toCharArray()
                            ?: "password".toCharArray()
                    )
                    setCertificateAlias(it.certAlias ?: "1")
                }
            }
        }

        fun applySslContextParameters(
            builder: AisecDapsDriverConfig.Builder,
            sslContextParameters: SSLContextParameters
        ): AisecDapsDriverConfig.Builder {
            return builder.apply {
                sslContextParameters.let {
                setKeyPassword(
                    it.keyManagers?.keyPassword?.toCharArray()
                        ?: "password".toCharArray()
                )
                it.keyManagers?.keyStore?.resource?.let { setKeyStorePath(Paths.get(it)) }
                setKeyStorePassword(
                    it.keyManagers?.keyStore?.password?.toCharArray()
                        ?: "password".toCharArray()
                )
                it.trustManagers?.trustManager?.let { setTrustManager(it) }
                it.trustManagers?.keyStore?.resource?.let { setTrustStorePath(Paths.get(it)) }
                setTrustStorePassword(
                    it.trustManagers?.keyStore?.password?.toCharArray()
                        ?: "password".toCharArray()
                )
                setKeyAlias(it.certAlias ?: "1")
            } }
        }
    }

}
