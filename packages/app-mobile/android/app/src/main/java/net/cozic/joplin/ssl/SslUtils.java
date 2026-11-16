package net.cozic.joplin.ssl;

import android.annotation.SuppressLint;

import java.security.KeyStore;
import java.util.Collections;
import java.util.Set;
import java.util.WeakHashMap;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.OkHttpClient;

public class SslUtils {

    @SuppressLint("TrustAllX509TrustManager")
    static final X509TrustManager TRUST_ALL_CERTS = new X509TrustManager() {

        @Override
        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {
        }

        @Override
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[]{};
        }
    };

    private static X509TrustManager defaultTrustManager = null;

    // Recreated when the client certificate changes. A new SSLContext also has a new TLS
    // session cache, so sessions negotiated with the previous identity are not resumed.
    // (Conscrypt does not support SSLSession.invalidate() on sessions from the cache.)
    private static SSLContext defaultContext = null;
    private static SSLContext trustyContext = null;

    private static final SSLSocketFactory defaultSocketFactory = new DelegatingSslSocketFactory(() -> getDefaultContext().getSocketFactory());
    private static final SSLSocketFactory trustySocketFactory = new DelegatingSslSocketFactory(() -> getTrustyContext().getSocketFactory());

    // Clients created by ClientCertificateHttpClientFactory. Clients derived from them
    // with newBuilder() share their connection pool, so evicting these is enough.
    private static final Set<OkHttpClient> clients = Collections.newSetFromMap(new WeakHashMap<>());

    static KeyManager[] keyManagers() {
        return new KeyManager[]{ ClientCertificateKeyManager.getInstance() };
    }

    // The platform default trust manager, which honours network_security_config.xml
    static synchronized X509TrustManager getDefaultTrustManager() {
        if (defaultTrustManager != null) return defaultTrustManager;
        try {
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init((KeyStore) null);
            for (TrustManager manager : factory.getTrustManagers()) {
                if (manager instanceof X509TrustManager) {
                    defaultTrustManager = (X509TrustManager) manager;
                    return defaultTrustManager;
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Could not get the default trust manager", e);
        }
        throw new IllegalStateException("No X509TrustManager available");
    }

    private static synchronized SSLContext getDefaultContext() {
        if (defaultContext == null) defaultContext = createContext(getDefaultTrustManager());
        return defaultContext;
    }

    private static synchronized SSLContext getTrustyContext() {
        if (trustyContext == null) trustyContext = createContext(TRUST_ALL_CERTS);
        return trustyContext;
    }

    private static SSLContext createContext(X509TrustManager trustManager) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keyManagers(), new TrustManager[]{ trustManager }, null);
            return context;
        } catch (Exception e) {
            throw new RuntimeException("Could not create SSL context", e);
        }
    }

    // Validates server certificates as usual and presents the selected client certificate, if any
    static SSLSocketFactory getSocketFactory() {
        return defaultSocketFactory;
    }

    // Accepts any server certificate ("Ignore TLS certificate errors"), but still
    // presents the selected client certificate, if any
    static SSLSocketFactory getTrustySocketFactory() {
        return trustySocketFactory;
    }

    static void registerClient(OkHttpClient client) {
        synchronized (clients) {
            clients.add(client);
        }
    }

    // After the client certificate has changed, idle connections and cached TLS sessions
    // still carry the previous identity, so they must not be reused.
    static void onClientCertificateChanged() {
        synchronized (SslUtils.class) {
            defaultContext = null;
            trustyContext = null;
        }
        synchronized (clients) {
            for (OkHttpClient client : clients) {
                client.connectionPool().evictAll();
            }
        }
    }
}
