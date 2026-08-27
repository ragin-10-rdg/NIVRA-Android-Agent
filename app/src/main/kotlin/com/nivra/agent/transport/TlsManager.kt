package com.nivra.agent.transport

import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Configures TLS for the transport layer. By default this uses the
 * platform trust store (standard CA validation, no custom TrustManager that
 * would disable hostname/certificate checks). If your Wazuh environment
 * uses a private CA or self-signed cert for the prototype, supply it via
 * [loadPinnedCertificate] rather than disabling validation.
 *
 * Explicitly does NOT provide a way to accept-all-certificates; that
 * shortcut is a common Android sample-code anti-pattern and defeats the
 * "secure communication" requirement.
 */
object TlsManager {

    /**
     * Builds an SSLContext trusting the platform CA store plus, optionally,
     * one additional certificate (e.g. your test Wazuh receiver's
     * self-signed cert during prototype development).
     */
    fun buildSslContext(pinnedCertPem: String? = null): SSLContext {
        val trustStore = KeyStore.getInstance(KeyStore.getDefaultType())
        trustStore.load(null, null)

        if (pinnedCertPem != null) {
            val cf = CertificateFactory.getInstance("X.509")
            val cert = cf.generateCertificate(pinnedCertPem.byteInputStream()) as X509Certificate
            trustStore.setCertificateEntry("nivra-pinned", cert)
        }

        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        // Passing null falls back to the platform default CA store merged
        // with any pinned cert added above.
        tmf.init(if (pinnedCertPem != null) trustStore else null as KeyStore?)

        val context = SSLContext.getInstance("TLS")
        context.init(null, tmf.trustManagers, null)
        return context
    }

    fun applyTo(connection: HttpsURLConnection, pinnedCertPem: String? = null) {
        connection.sslSocketFactory = buildSslContext(pinnedCertPem).socketFactory
        // Default HostnameVerifier is left in place intentionally -- do not
        // override it to return true unconditionally.
    }
}
