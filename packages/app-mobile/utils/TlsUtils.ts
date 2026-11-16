import { Platform, NativeModules } from 'react-native';

export default async function setIgnoreTlsErrors(ignore: boolean): Promise<boolean> {
	if (Platform.OS === 'android') {
		return await NativeModules.SslModule.setIgnoreTlsErrors(ignore);
	} else {
		return false;
	}
}

// Client certificates (mutual TLS) are picked from the Android KeyChain, so this is Android only
export const clientCertificatesSupported = () => Platform.OS === 'android';

export interface ClientCertificate {
	alias: string;
	// The server the certificate was selected for. It is only presented to this server.
	host: string|null;
	port: number;
}

// Gets the server from a sync target URL. A URL that can't be parsed is not an error:
// the certificate is then simply not presented to any server.
export const hostAndPortFromUrl = (url: string): { host: string|null; port: number } => {
	const match = (url || '').trim().match(/^(https?):\/\/(?:[^@/?#]*@)?(\[[^\]]+\]|[^:/?#]+)(?::(\d+))?/i);
	if (!match) return { host: null, port: -1 };
	const defaultPort = match[1].toLowerCase() === 'https' ? 443 : 80;
	return { host: match[2], port: match[3] ? Number(match[3]) : defaultPort };
};

const normaliseHost = (host: string|null) => {
	if (!host) return null;
	return host.replace(/^\[(.*)\]$/, '$1').toLowerCase();
};

// Whether the selected certificate is used for the server of the given sync target URL
export const isCertificateForServer = (certificate: ClientCertificate, serverUrl: string) => {
	const { host, port } = hostAndPortFromUrl(serverUrl);
	if (!host || !certificate.host) return false;
	return normaliseHost(host) === normaliseHost(certificate.host) && (certificate.port <= 0 || certificate.port === port);
};

// Shows the system certificate picker. The selected certificate is only presented to the
// server of serverUrl. Resolves with the selected alias, or null if
// the user cancelled, in which case the previous selection is kept.
export async function selectClientCertificate(serverUrl: string): Promise<string|null> {
	if (!clientCertificatesSupported()) return null;
	const { host, port } = hostAndPortFromUrl(serverUrl);
	return await NativeModules.SslModule.selectClientCertificate(host, port);
}

export async function getClientCertificate(): Promise<ClientCertificate|null> {
	if (!clientCertificatesSupported()) return null;
	return await NativeModules.SslModule.getClientCertificate();
}

export async function clearClientCertificate(): Promise<void> {
	if (!clientCertificatesSupported()) return;
	await NativeModules.SslModule.clearClientCertificate();
}
