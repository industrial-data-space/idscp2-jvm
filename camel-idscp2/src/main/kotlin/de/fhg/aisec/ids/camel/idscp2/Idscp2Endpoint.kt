/*-
 * ========================LICENSE_START=================================
 * camel-idscp2
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
package de.fhg.aisec.ids.camel.idscp2

import de.fhg.aisec.ids.idscp2.api.configuration.AttestationConfig
import de.fhg.aisec.ids.idscp2.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.daps.aisecdaps.AisecDapsDriver
import de.fhg.aisec.ids.idscp2.daps.aisecdaps.AisecDapsDriverConfig
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.NativeTlsConfiguration
import de.fhg.aisec.ids.idscp2.keystores.KeyStoreUtil
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

        val transportSslContextParameters = transportSslContextParameters ?: sslContextParameters
        // If no Builder has been passed, perform configuration based on passed individual parameters
        if (secureChannelConfigurationBuilder == null) {
            transportSslContextParameters?.let {
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
                applySslContextParameters(dapsDriverConfigBuilder, it, transportSslContextParameters)
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
            dapsSslContextParameters: SSLContextParameters,
            transportSslContextParameters: SSLContextParameters? = null
        ): AisecDapsDriverConfig.Builder {
            return builder.apply {
                dapsSslContextParameters.let { scp ->
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
                // Load transport SSL certificates and create fingerprints
                transportSslContextParameters?.let { scp ->
                    scp.keyManagers?.keyStore?.resource?.let { Paths.get(it) }?.let { keyStorePath ->
                        scp.keyManagers?.keyStore?.password?.toCharArray()?.let { keyStorePassword ->
                            val ks = KeyStoreUtil.loadKeyStore(keyStorePath, keyStorePassword)
                            loadTransportCertsFromKeystore(ks)
                        }
                    }
                }
            }
        }
    }
}
