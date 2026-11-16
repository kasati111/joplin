import * as React from 'react';
import { useCallback, useEffect, useState } from 'react';
import { Alert } from 'react-native';
import { _ } from '@joplin/lib/locale';
import Logger from '@joplin/utils/Logger';
import SyncTargetRegistry from '@joplin/lib/SyncTargetRegistry';
import SettingsButton from './SettingsButton';
import { ConfigScreenStyles } from './configScreenStyles';
import { ClientCertificate, clearClientCertificate, clientCertificatesSupported, getClientCertificate, isCertificateForServer, selectClientCertificate } from '../../../utils/TlsUtils';

const logger = Logger.create('ClientCertificateButton');

// Sync targets that talk HTTP(S) to a server the user controls, and can therefore
// sit behind a reverse proxy that requires a client certificate.
const supportedSyncTargets = () => [
	SyncTargetRegistry.nameToId('nextcloud'),
	SyncTargetRegistry.nameToId('webdav'),
	SyncTargetRegistry.nameToId('joplinServer'),
	SyncTargetRegistry.nameToId('joplinServerSaml'),
];

export const showClientCertificateButton = (syncTargetId: number) => {
	return clientCertificatesSupported() && supportedSyncTargets().includes(syncTargetId);
};

export const clientCertificateButtonTitle = () => _('Client certificate');

interface Props {
	styles: ConfigScreenStyles;
	// URL of the sync target, shown by the system dialog
	serverUrl: string;
}

const ClientCertificateButton: React.FC<Props> = props => {
	const [certificate, setCertificate] = useState<ClientCertificate|null>(null);
	const alias = certificate?.alias ?? null;

	const refresh = useCallback(async () => {
		setCertificate(await getClientCertificate());
	}, []);

	useEffect(() => {
		let cancelled = false;
		void (async () => {
			const current = await getClientCertificate();
			if (!cancelled) setCertificate(current);
		})();
		return () => {
			cancelled = true;
		};
	}, []);

	const onSelect = useCallback(async () => {
		try {
			const selectedAlias = await selectClientCertificate(props.serverUrl);
			if (selectedAlias) await refresh();
		} catch (error) {
			logger.error('Could not select client certificate', error);
			Alert.alert(_('Error'), error.message);
		}
	}, [props.serverUrl, refresh]);

	const onRemove = useCallback(async () => {
		await clearClientCertificate();
		setCertificate(null);
	}, []);

	const onPress = useCallback(() => {
		if (!alias) {
			void onSelect();
			return;
		}

		Alert.alert(clientCertificateButtonTitle(), _('Selected certificate: %s', alias), [
			{ text: _('Change'), onPress: () => {
				void onSelect();
			} },
			{ text: _('Remove'), style: 'destructive', onPress: () => {
				void onRemove();
			} },
			{ text: _('Cancel'), style: 'cancel' },
		]);
	}, [alias, onSelect, onRemove]);

	let description;
	if (!certificate) {
		description = _('If your server requires a client certificate (mutual TLS), install it in the Android settings and select it here.');
	} else if (isCertificateForServer(certificate, props.serverUrl)) {
		description = _('Selected certificate: %s', certificate.alias);
	} else {
		// For example, the sync URL has changed since the certificate was selected
		description = _('The certificate %s was selected for another server. Select it again to use it with this server.', certificate.alias);
	}

	return (
		<SettingsButton
			title={clientCertificateButtonTitle()}
			description={description}
			clickHandler={onPress}
			styles={props.styles}
		/>
	);
};

export default ClientCertificateButton;
