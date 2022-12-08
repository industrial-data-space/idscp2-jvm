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
    var idscp2Configuration: Idscp2Configuration?
    var secureChannelConfigurationBuilder: NativeTlsConfiguration.Builder?
    var secureChannelConfiguration: NativeTlsConfiguration

    fun Idscp2Endpoint.doCommonEndpointConfiguration(
        secureChannelConfigurationBlock: ((NativeTlsConfiguration.Builder) -> Unit)? = null
    ) {
        // Use the provided NativeTlsConfiguration.Builder, or create a new one
        val secureChannelConfigBuilder = secureChannelConfigurationBuilder ?: run { NativeTlsConfiguration.Builder() }

        // If no Builder has been passed, perform configuration based on passed individual parameters
        if (secureChannelConfigurationBuilder == null) {
            (transportSslContextParameters ?: sslContextParameters)?.let {
                applySslContextParameters(secureChannelConfigBuilder, it)
            }
        }

        // Always set (or overwrite) the host and port with information passed by component URI
        val remainingMatcher = URI_REGEX.matcher(remaining)
        require(remainingMatcher.matches()) { "$remaining is not a valid URI remainder, must be \"host:port\"." }
        val matchResult = remainingMatcher.toMatchResult()
        val host = matchResult.group(1)
        val port = matchResult.group(2)?.toInt() ?: NativeTlsConfiguration.DEFAULT_SERVER_PORT
        secureChannelConfigBuilder.setHost(host).setServerPort(port)
        // Always execute secureChannelConfigurationBlock (hostname verification cannot be disabled via beans)
        secureChannelConfigurationBlock?.invoke(secureChannelConfigBuilder)
        // Finalize the NativeTlsConfiguration
        secureChannelConfiguration = secureChannelConfigBuilder.build()

        if (idscp2Configuration == null) {
            // create attestation config
            val localAttestationConfig = AttestationConfig.Builder()
                .setSupportedRaSuite(supportedRaSuites.split('|').toTypedArray())
                .setExpectedRaSuite(expectedRaSuites.split('|').toTypedArray())
                .setRaTimeoutDelay(dapsRaTimeoutDelay)
                .build()

            // create daps config
            val dapsDriverConfigBuilder = AisecDapsDriverConfig.Builder()
                .setDapsUrl(Utils.dapsUrlProducer())

            (dapsSslContextParameters ?: sslContextParameters)?.let {
                applySslContextParameters(dapsDriverConfigBuilder, it)
            }

            // create idscp config
            idscp2Configuration = Idscp2Configuration.Builder()
                .setAttestationConfig(localAttestationConfig)
                .setDapsDriver(AisecDapsDriver(dapsDriverConfigBuilder.build()))
                .build()
        }
    }

    companion object {
        private val URI_REGEX = Pattern.compile("(.*?)(?::(\\d+))?/?$")

        fun applySslContextParameters(
            builder: NativeTlsConfiguration.Builder,
            sslContextParameters: SSLContextParameters
        ): NativeTlsConfiguration.Builder {
            return builder.apply {
                sslContextParameters.let { scp ->
                    setKeyPassword(
                        scp.keyManagers?.keyPassword?.toCharArray()
                            ?: "password".toCharArray()
                    )
                    scp.keyManagers?.keyStore?.resource?.let { setKeyStorePath(Paths.get(it)) }
                    scp.keyManagers?.keyStore?.type?.let { setKeyStoreKeyType(it) }
                    setKeyStorePassword(
                        scp.keyManagers?.keyStore?.password?.toCharArray()
                            ?: "password".toCharArray()
                    )
                    scp.trustManagers?.trustManager?.let { setTrustManager(it) }
                    scp.trustManagers?.keyStore?.resource?.let { setTrustStorePath(Paths.get(it)) }
                    setTrustStorePassword(
                        scp.trustManagers?.keyStore?.password?.toCharArray()
                            ?: "password".toCharArray()
                    )
                    setCertificateAlias(scp.certAlias ?: "1")
                }
            }
        }

        fun applySslContextParameters(
            builder: AisecDapsDriverConfig.Builder,
            sslContextParameters: SSLContextParameters
        ): AisecDapsDriverConfig.Builder {
            return builder.apply {
                sslContextParameters.let { scp ->
                    setKeyPassword(
                        scp.keyManagers?.keyPassword?.toCharArray()
                            ?: "password".toCharArray()
                    )
                    scp.keyManagers?.keyStore?.resource?.let { setKeyStorePath(Paths.get(it)) }
                    setKeyStorePassword(
                        scp.keyManagers?.keyStore?.password?.toCharArray()
                            ?: "password".toCharArray()
                    )
                    scp.trustManagers?.trustManager?.let { setTrustManager(it) }
                    scp.trustManagers?.keyStore?.resource?.let { setTrustStorePath(Paths.get(it)) }
                    setTrustStorePassword(
                        scp.trustManagers?.keyStore?.password?.toCharArray()
                            ?: "password".toCharArray()
                    )
                    setKeyAlias(scp.certAlias ?: "1")
                }
            }
        }
    }

}
