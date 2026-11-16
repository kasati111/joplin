package net.cozic.joplin.ssl;

import android.content.Context;

import androidx.annotation.NonNull;

import com.RNFetchBlob.RNFetchBlobUtils;
import com.facebook.react.modules.network.OkHttpClientFactory;
import com.facebook.react.modules.network.OkHttpClientProvider;

import java.io.File;

import okhttp3.Cache;
import okhttp3.OkHttpClient;

/**
 * Creates the OkHttp clients used by React Native's networking module (fetch) and by
 * rn-fetch-blob (attachments), so that both present the selected client certificate.
 * Apart from the socket factory, the clients are configured like React Native's defaults.
 */
public class ClientCertificateHttpClientFactory implements OkHttpClientFactory {

    // Same location and size as React Native's default. The factory is called more than
    // once per process, and OkHttp requires a cache directory to be used by one Cache only.
    private static final int CACHE_SIZE = 10 * 1024 * 1024;

    private final Context context;
    private Cache cache = null;

    public ClientCertificateHttpClientFactory(Context context) {
        this.context = context.getApplicationContext();
        // rn-fetch-blob builds its own socket factory when TLS errors are ignored ("trusty")
        RNFetchBlobUtils.setClientKeyManagers(SslUtils.keyManagers());
    }

    private synchronized Cache cache() {
        if (cache == null) cache = new Cache(new File(context.getCacheDir(), "http-cache"), CACHE_SIZE);
        return cache;
    }

    @NonNull
    @Override
    public OkHttpClient createNewNetworkModuleClient() {
        OkHttpClient client = OkHttpClientProvider.createClientBuilder(context, 0)
                .cache(cache())
                .sslSocketFactory(SslUtils.getSocketFactory(), SslUtils.getDefaultTrustManager())
                .build();
        SslUtils.registerClient(client);
        return client;
    }
}
