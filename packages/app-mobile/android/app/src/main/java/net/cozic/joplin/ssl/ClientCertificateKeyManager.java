package net.cozic.joplin.ssl;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.KeyChain;
import android.security.KeyChainException;
import android.util.Log;

import androidx.annotation.Nullable;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedKeyManager;

/**
 * Presents a client certificate (mutual TLS) that the user has selected from the
 * Android KeyChain. The private key never leaves the KeyChain; this class only
 * keeps a reference to it once access has been granted by the system dialog.
 *
 * The certificate is only presented to the server it was selected for (host and
 * port of the sync target), not to other servers the app connects to.
 *
 * When no certificate is selected, every method returns null, which is exactly
 * what happens without a key manager, so connections are unaffected.
 */
public class ClientCertificateKeyManager extends X509ExtendedKeyManager {

    private static final String TAG = "JOPLIN";
    private static final String PREFERENCES_NAME = "net.cozic.joplin.ssl";
    private static final String ALIAS_KEY = "clientCertificateAlias";
    private static final String HOST_KEY = "clientCertificateHost";
    private static final String PORT_KEY = "clientCertificatePort";

    private static ClientCertificateKeyManager instance = null;

    private final Context context;
    private String alias;
    // The server the certificate was selected for
    private String host;
    private int port;
    private PrivateKey privateKey = null;
    private X509Certificate[] certificateChain = null;

    private ClientCertificateKeyManager(Context context) {
        this.context = context.getApplicationContext();
        SharedPreferences preferences = preferences();
        this.alias = preferences.getString(ALIAS_KEY, null);
        this.host = preferences.getString(HOST_KEY, null);
        this.port = preferences.getInt(PORT_KEY, -1);
    }

    // Must be called once, before any network client is created (see MainApplication)
    public static synchronized void initialize(Context context) {
        if (instance == null) instance = new ClientCertificateKeyManager(context);
    }

    public static synchronized ClientCertificateKeyManager getInstance() {
        if (instance == null) throw new IllegalStateException("ClientCertificateKeyManager has not been initialized");
        return instance;
    }

    private SharedPreferences preferences() {
        return context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE);
    }

    @Nullable
    public synchronized String getAlias() {
        return alias;
    }

    @Nullable
    public synchronized String getHost() {
        return host;
    }

    public synchronized int getPort() {
        return port;
    }

    // Selects a certificate for the given server, or clears the selection if newAlias is null
    public synchronized void setCertificate(@Nullable String newAlias, @Nullable String newHost, int newPort) {
        alias = newAlias;
        host = newAlias == null ? null : normaliseHost(newHost);
        port = newAlias == null ? -1 : newPort;
        privateKey = null;
        certificateChain = null;

        SharedPreferences.Editor editor = preferences().edit();
        if (alias == null) {
            editor.remove(ALIAS_KEY).remove(HOST_KEY).remove(PORT_KEY);
        } else {
            editor.putString(ALIAS_KEY, alias);
            if (host == null) {
                editor.remove(HOST_KEY);
            } else {
                editor.putString(HOST_KEY, host);
            }
            editor.putInt(PORT_KEY, port);
        }
        editor.apply();
    }

    // "[2001:db8::1]" (as in a URL) and "2001:db8::1" (as reported by a socket) are the same host
    @Nullable
    private static String normaliseHost(@Nullable String value) {
        if (value == null) return null;
        String result = value.trim();
        if (result.startsWith("[") && result.endsWith("]")) result = result.substring(1, result.length() - 1);
        return result.isEmpty() ? null : result;
    }

    private synchronized boolean isSelectedServer(@Nullable String peerHost, int peerPort) {
        if (host == null) return false;
        String normalised = normaliseHost(peerHost);
        return host.equalsIgnoreCase(normalised) && (port <= 0 || port == peerPort);
    }

    // KeyChain calls may block, which is fine here: they are only made during
    // the TLS handshake, which runs on the network threads.
    private synchronized boolean loadCertificate() {
        if (alias == null) return false;
        if (privateKey != null && certificateChain != null) return true;

        try {
            privateKey = KeyChain.getPrivateKey(context, alias);
            certificateChain = KeyChain.getCertificateChain(context, alias);
        } catch (KeyChainException e) {
            Log.w(TAG, "Could not load client certificate \"" + alias + "\"", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        if (privateKey == null || certificateChain == null) {
            // For example, the certificate has been removed from the system or access has been revoked
            privateKey = null;
            certificateChain = null;
            return false;
        }
        return true;
    }

    @Nullable
    private synchronized String selectedAlias() {
        return loadCertificate() ? alias : null;
    }

    @Override
    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        String peerHost = null;
        int peerPort = -1;

        // Sockets created by DelegatingSslSocketFactory (fetch, attachments)
        DelegatingSslSocketFactory.Destination destination = DelegatingSslSocketFactory.destinationOf(socket);
        if (destination != null) {
            peerHost = destination.host;
            peerPort = destination.port;
        } else if (socket instanceof SSLSocket) {
            // Other sockets, for example from rn-fetch-blob when TLS errors are ignored
            SSLSession session = ((SSLSocket) socket).getHandshakeSession();
            if (session != null) {
                peerHost = session.getPeerHost();
                peerPort = session.getPeerPort();
            }
        }

        if (!isSelectedServer(peerHost, peerPort)) {
            if (getAlias() != null) Log.i(TAG, "Not presenting the client certificate to " + peerHost + ":" + peerPort);
            return null;
        }
        return selectedAlias();
    }

    @Override
    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
        if (engine == null || !isSelectedServer(engine.getPeerHost(), engine.getPeerPort())) return null;
        return selectedAlias();
    }

    @Override
    public synchronized X509Certificate[] getCertificateChain(String requestedAlias) {
        if (requestedAlias == null || !requestedAlias.equals(alias) || !loadCertificate()) return null;
        return certificateChain;
    }

    @Override
    public synchronized PrivateKey getPrivateKey(String requestedAlias) {
        if (requestedAlias == null || !requestedAlias.equals(alias) || !loadCertificate()) return null;
        return privateKey;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        String selected = selectedAlias();
        return selected == null ? null : new String[]{ selected };
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return null;
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return null;
    }
}
