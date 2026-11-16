package net.cozic.joplin.ssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;

import javax.net.ssl.SSLSocketFactory;

/**
 * An SSLSocketFactory that forwards to the factory of the current SSLContext. OkHttp keeps
 * the socket factory of a client for its whole life, so this indirection lets SslUtils
 * replace the SSLContext (and with it the TLS session cache) when the client certificate
 * changes, without having to rebuild the clients.
 *
 * It also remembers the host and port each TLS socket was created for, so that the key
 * manager can check the destination before presenting the client certificate.
 */
class DelegatingSslSocketFactory extends SSLSocketFactory {

    interface Delegate {
        SSLSocketFactory get();
    }

    static final class Destination {
        final String host;
        final int port;

        Destination(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }

    private static final Map<Socket, Destination> destinations = Collections.synchronizedMap(new WeakHashMap<>());

    private final Delegate delegate;

    DelegatingSslSocketFactory(Delegate delegate) {
        this.delegate = delegate;
    }

    static Destination destinationOf(Socket socket) {
        return socket == null ? null : destinations.get(socket);
    }

    private Socket remember(Socket socket, String host, int port) {
        if (socket != null && host != null) destinations.put(socket, new Destination(host, port));
        return socket;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return delegate.get().getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.get().getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
        return remember(delegate.get().createSocket(socket, host, port, autoClose), host, port);
    }

    @Override
    public Socket createSocket() throws IOException {
        return delegate.get().createSocket();
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return remember(delegate.get().createSocket(host, port), host, port);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        return remember(delegate.get().createSocket(host, port, localHost, localPort), host, port);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return remember(delegate.get().createSocket(host, port), host.getHostAddress(), port);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return remember(delegate.get().createSocket(address, port, localAddress, localPort), address.getHostAddress(), port);
    }
}
