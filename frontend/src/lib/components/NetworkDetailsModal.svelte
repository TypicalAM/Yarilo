<script lang="ts">
	import { fade } from 'svelte/transition';
	import { Button } from './ui/button';
	import { get } from 'svelte/store';
	import { client, activeSnifferId, notifications, isLoading, selectedNetwork } from '../stores';
	import { Input } from './ui/input';
	import type { AccessPointInfo, ClientInfo } from '../proto/service';

	export let show = false;
	export let bssid = '';
	export let onClose = () => {};
	export let onFocusChange: () => void = () => {};

	let networkDetails: AccessPointInfo | null = null;
	let isFocused = false;
	let password = '';
	let hash: string | null = null;
	let showHashModal = false;

	const channelTypeMap = {
		0: 'No HT',
		1: 'HT20',
		2: 'HT40-',
		3: 'HT40+',
		4: 'VHT80',
		5: 'VHT80+80',
		6: 'VHT160'
	};

	const securityMap = {
		0: 'Open',
		1: 'WEP',
		2: 'WPA',
		3: 'WPA2-Personal',
		4: 'WPA2-Enterprise',
		5: 'WPA3-Personal',
		6: 'WPA3-Enterprise'
	};

	const wifiStandardMap = {
		0: '802.11a',
		1: '802.11b',
		2: '802.11g',
		3: '802.11n',
		4: '802.11ac',
		5: '802.11ax'
	};

	async function checkFocusStatus() {
		const currentClient = get(client);
		const snifferId = get(activeSnifferId);

		if (!currentClient || !snifferId) return;

		try {
			const response = await currentClient.focusGetActive({
				snifferUuid: snifferId
			});
			isFocused = response.response.bssid === bssid;
		} catch (e) {
			console.error('Failed to check focus status:', e);
		}
	}

	async function toggleFocus() {
		const currentClient = get(client);
		const snifferId = get(activeSnifferId);

		if (!currentClient || !snifferId) {
			notifications.add('Client or sniffer not initialized', 'error');
			return;
		}

		try {
			isLoading.set(true);
			if (isFocused) {
				await currentClient.focusStop({
					snifferUuid: snifferId
				});
				notifications.add('Focus stopped', 'success');
			} else {
				await currentClient.focusStart({
					snifferUuid: snifferId,
					bssid: bssid
				});
				notifications.add('Focus started', 'success');
			}
			isFocused = !isFocused;
			onFocusChange();
		} catch (e) {
			console.error('Focus toggle failed:', e);
			notifications.add('Failed to toggle focus', 'error');
		} finally {
			isLoading.set(false);
		}
	}

	async function loadNetworkDetails() {
		const currentClient = get(client);
		const snifferId = get(activeSnifferId);

		if (!currentClient || !snifferId) return;

		try {
			isLoading.set(true);
			const response = await currentClient.accessPointGet({
				snifferUuid: snifferId,
				bssid: bssid
			});

			networkDetails = response.response.ap || null;
			await checkFocusStatus();
		} catch (e) {
			console.error('Failed to load network details:', e);
			notifications.add('Failed to load network details', 'error');
		} finally {
			isLoading.set(false);
		}
	}

	async function submitPassword() {
		const currentClient = get(client);
		const snifferId = get(activeSnifferId);

		if (!currentClient || !snifferId) {
			notifications.add('Client or sniffer not initialized', 'error');
			return;
		}

		try {
			isLoading.set(true);
			const response = await currentClient.accessPointProvidePassword({
				snifferUuid: snifferId,
				bssid: bssid,
				password
			});

			if (response.response.state === 0) {
				notifications.add('Password accepted', 'success');
				selectedNetwork.set(
					networkDetails ? { bssid: networkDetails.bssid, ssid: networkDetails.ssid } : null
				);
				password = '';
			}
		} catch (e) {
			console.error('Password submission failed:', e);
			notifications.add('Failed to submit password', 'error');
		} finally {
			isLoading.set(false);
		}
	}

	$: if (show && bssid) {
		loadNetworkDetails();
	}

	async function ignoreNetwork() {
		const currentClient = get(client);
		const snifferId = get(activeSnifferId);

		if (!currentClient || !snifferId || !networkDetails) {
			notifications.add('Missing required configuration', 'error');
			return;
		}

		try {
			isLoading.set(true);
			await currentClient.accessPointIgnore({
				snifferUuid: snifferId,
				bssid: networkDetails.bssid,
				useSsid: false,
				ssid: ''
			});

			notifications.add('Network added to ignored list', 'success');
			onClose();
		} catch (e) {
			console.error('Failed to ignore network:', e);
			notifications.add('Failed to ignore network', 'error');
		} finally {
			isLoading.set(false);
		}
	}

	async function deauthNetwork() {
		const currentClient = get(client);
		const snifferId = get(activeSnifferId);

		if (!currentClient || !snifferId) {
			notifications.add('Missing required configuration', 'error');
			return;
		}

		try {
			isLoading.set(true);
			await currentClient.accessPointDeauth({
				snifferUuid: snifferId,
				bssid: bssid
			});

			notifications.add('Network deauthentication successful', 'success');
		} catch (e) {
			console.error('Failed to deauth network:', e);
			notifications.add('Network deauthentication failed', 'error');
		} finally {
			isLoading.set(false);
		}
	}

	async function deauthClient(clientInfo: ClientInfo) {
		const currentClient = get(client);
		const snifferId = get(activeSnifferId);

		if (!currentClient || !snifferId) {
			notifications.add('Missing required configuration', 'error');
			return;
		}

		try {
			isLoading.set(true);
			await currentClient.accessPointDeauthClient({
				snifferUuid: snifferId,
				bssid: bssid,
				clientAddr: clientInfo.hwaddr
			});

			const displayName = clientInfo.hostname || clientInfo.hwaddr;
			notifications.add(`Client ${displayName} deauthentication successful`, 'success');
		} catch (e) {
			console.error('Failed to deauth client:', e);
			notifications.add('Client deauthentication failed', 'error');
		} finally {
			isLoading.set(false);
		}
	}

	async function copyHash(clientInfo: ClientInfo) {
		const currentClient = get(client);
		const snifferId = get(activeSnifferId);

		if (!currentClient || !snifferId || !networkDetails) {
			notifications.add('Missing required configuration', 'error');
			return;
		}

		try {
			isLoading.set(true);
			const response = await currentClient.accessPointGetHash({
				snifferUuid: snifferId,
				bssid: networkDetails.bssid,
				clientAddr: clientInfo.hwaddr
			});

			hash = response.response.hc22000;
			showHashModal = true;
		} catch (e) {
			console.error('Failed to get hash:', e);
			notifications.add('Failed to get hash', 'error');
		} finally {
			isLoading.set(false);
		}
	}
</script>

<div
	class="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto overflow-x-hidden"
	role="dialog"
	aria-modal="true"
>
	<!-- Modal's background  -->
	<div class="fixed inset-0 bg-black/50" on:click={onClose}></div>

	<!-- Modal contener -->
	<div class="relative z-50 m-4 max-h-[90vh] w-full max-w-3xl overflow-y-auto rounded-lg bg-white">
		<!-- Header -->
		<div class="flex items-center justify-between border-b p-4">
			<h2 class="text-xl font-semibold">Network Details</h2>
			<button class="text-gray-500 hover:text-gray-700" on:click={onClose}>
				<svg
					xmlns="http://www.w3.org/2000/svg"
					class="h-6 w-6"
					fill="none"
					viewBox="0 0 24 24"
					stroke="currentColor"
				>
					<path
						stroke-linecap="round"
						stroke-linejoin="round"
						stroke-width="2"
						d="M6 18L18 6M6 6l12 12"
					/>
				</svg>
			</button>
		</div>

		<div class="p-6">
			{#if networkDetails}
				<div class="space-y-6">
					<!-- Action buttons -->
					<div class="flex gap-2">
						<Button
							variant={isFocused ? 'destructive' : 'default'}
							on:click={toggleFocus}
							disabled={$isLoading}
						>
							{isFocused ? 'Stop Focus' : 'Start Focus'}
						</Button>
						<Button variant="outline" on:click={loadNetworkDetails} disabled={$isLoading}>
							<svg
								xmlns="http://www.w3.org/2000/svg"
								class="mr-2 h-4 w-4"
								viewBox="0 0 20 20"
								fill="currentColor"
							>
								<path
									fill-rule="evenodd"
									d="M4 2a1 1 0 011 1v2.101a7.002 7.002 0 0111.601 2.566 1 1 0 11-1.885.666A5.002 5.002 0 005.999 7H9a1 1 0 010 2H4a1 1 0 01-1-1V3a1 1 0 011-1zm.008 9.057a1 1 0 011.276.61A5.002 5.002 0 0014.001 13H11a1 1 0 110-2h5a1 1 0 011 1v5a1 1 0 11-2 0v-2.101a7.002 7.002 0 01-11.601-2.566 1 1 0 01.61-1.276z"
									clip-rule="evenodd"
								/>
							</svg>
							Refresh
						</Button>
						<Button variant="outline" on:click={ignoreNetwork} disabled={$isLoading}>
							Ignore Network
						</Button>
						<Button variant="destructive" on:click={deauthNetwork} disabled={$isLoading}>
							Deauth Network
						</Button>
					</div>

					<!-- Network details -->
					<div class="grid grid-cols-2 gap-4">
						<div>
							<p class="text-sm text-gray-500">SSID</p>
							<p class="font-medium">{networkDetails.ssid || 'Hidden Network'}</p>
						</div>
						<div>
							<p class="text-sm text-gray-500">BSSID</p>
							<p class="font-medium">{networkDetails.bssid}</p>
						</div>
						<div>
							<p class="text-sm text-gray-500">Channels</p>
							{#each networkDetails.supportedChanels as info}
								<p class="font-medium">
									Channel: {info.channel} ({channelTypeMap[info.type]})
								</p>
							{/each}
						</div>
						<!-- Security -->
						<div>
							<p class="text-sm text-gray-500">Security</p>
							<p class="font-medium">
								{networkDetails.security.map((s) => securityMap[s]).join(', ')}
							</p>
						</div>
						<div>
							<p class="text-sm text-gray-500">Protected Management Frames</p>
							<div class="space-y-1">
								<p class="text-sm">Capable: {networkDetails.pmfCapable ? 'Yes' : 'No'}</p>
								<p class="text-sm">Required: {networkDetails.pmfRequired ? 'Yes' : 'No'}</p>
							</div>
						</div>
						<!-- WiFi Standards -->
						<div>
							<p class="text-sm text-gray-500">Supported Standards</p>
							<p class="font-medium">
								{networkDetails.supportedStandards.map((s) => wifiStandardMap[s.std]).join(', ')}
							</p>
						</div>
						<div>
							<p class="text-sm text-gray-500">Packets</p>
							<div class="space-y-1">
								<p class="text-sm">Encrypted: {networkDetails.encryptedPacketCount}</p>
								<p class="text-sm">Decrypted: {networkDetails.decryptedPacketCount}</p>
							</div>
						</div>

						<!-- Password Section -->
						<div class="col-span-2">
							<Input
								type="password"
								placeholder="Network password (optional)"
								bind:value={password}
							/>
							<Button
								variant="default"
								on:click={submitPassword}
								disabled={!password || $isLoading}
								class="mt-2 w-full"
							>
								Submit Password
							</Button>
						</div>
					</div>

					<!-- Connected Clients -->
					<div class="mt-8">
						<h3 class="mb-4 text-lg font-medium">Connected Clients</h3>
						{#if networkDetails.clients.length === 0}
							<p class="text-gray-500">No clients connected</p>
						{:else}
							<div class="space-y-4">
								{#each networkDetails.clients as client}
									<div class="rounded-lg border p-4">
										<div class="space-y-4">
											<div class="grid grid-cols-2 gap-4">
												<div>
													<p class="text-sm text-gray-500">Hostname</p>
													<p class="font-medium">{client.hostname || 'Unknown'}</p>
												</div>
												<div>
													<p class="text-sm text-gray-500">MAC Address</p>
													<p class="font-mono text-sm">{client.hwaddr}</p>
												</div>
												{#if client.ipv4}
													<div>
														<p class="text-sm text-gray-500">IPv4</p>
														<p class="font-medium">{client.ipv4}</p>
													</div>
												{/if}
												{#if client.radioInfo.rssi}
													<div>
														<p class="text-sm text-gray-500">Signal Strength</p>
														<p class="font-medium">
															{client.radioInfo.rssi} dBm
														</p>
													</div>
												{/if}
												<div>
													<p class="text-sm text-gray-500">Sent Unicast Packets</p>
													<p class="font-medium">{client.sentUnicast}</p>
												</div>
												<div>
													<p class="text-sm text-gray-500">Group Packets Sent</p>
													<p class="font-medium">{client.sentTotal - client.sentUnicast}</p>
												</div>
												<div>
													<p class="text-sm text-gray-500">Packets Received</p>
													<p class="font-medium">{client.received}</p>
												</div>
												<div>
													<p class="text-sm text-gray-500">PMF Active</p>
													<p class="font-medium">{client.pmfActive ? 'Yes' : 'No'}</p>
												</div>
												{#if client.router}
													<div>
														<p class="text-sm text-gray-500">Router</p>
														<p class="font-medium">{client.router ? 'Yes' : 'No'}</p>
													</div>
												{/if}
												{#if client.currentEapolPktCount}
													<div>
														<p class="text-sm text-gray-500">Current EAPOL Handshake Count</p>
														<p class="font-medium">{client.currentEapolPktCount}</p>
													</div>
												{/if}
											</div>

											<!-- Clients handshakes -->
											{#if client.windows.length > 0}
												<div class="rounded bg-gray-50 p-3">
													<p class="mb-2 text-sm text-gray-500">Handshakes</p>
													<div class="space-y-2">
														{#each client.windows as window}
															{#if window.authPacketCount > 0}
																<div class="grid grid-cols-2 gap-2 text-sm">
																	<div>
																		<span class="text-gray-500">Count: </span>
																		<span class="font-medium">
																			{window.decrypted
																				? 'Complete'
																				: `${window.authPacketCount}/4`}
																		</span>
																	</div>
																	<div>
																		<span class="text-gray-500">Status: </span>
																		<span
																			class="font-medium {window.decrypted
																				? 'text-green-600'
																				: 'text-yellow-600'}"
																		>
																			{window.decrypted ? 'Decrypted' : 'Pending'}
																		</span>
																	</div>
																	{#if window.decrypted && window.ptk}
																		<div class="col-span-2">
																			<span class="text-gray-500">PTK: </span>
																			<span class="font-mono text-xs"
																				>{window.ptk.substring(0, 20)}...</span
																			>
																		</div>
																	{/if}
																</div>
															{/if}
														{/each}
													</div>
												</div>
											{/if}
											<!-- Copy hash button -->
											<Button
												variant="outline"
												on:click={() => copyHash(client)}
												disabled={$isLoading || !client.windows.some((w) => w.authPacketCount > 0)}
												size="sm"
												class="mr-2"
											>
												<svg
													xmlns="http://www.w3.org/2000/svg"
													class="mr-2 h-4 w-4"
													fill="none"
													viewBox="0 0 24 24"
													stroke="currentColor"
												>
													<path
														stroke-linecap="round"
														stroke-linejoin="round"
														stroke-width="2"
														d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"
													/>
												</svg>
												Copy Hash
											</Button>
											<Button
												variant="destructive"
												on:click={() => deauthClient(client)}
												disabled={$isLoading}
												size="sm"
											>
												Deauthenticate Client
											</Button>
										</div>
									</div>
								{/each}
							</div>
						{/if}
					</div>
				</div>
			{:else}
				<div class="flex h-32 items-center justify-center">
					<div class="h-8 w-8 animate-spin rounded-full border-b-2 border-gray-900"></div>
				</div>
			{/if}
		</div>
	</div>
	{#if showHashModal && hash}
		<div
			class="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto overflow-x-hidden"
		>
			<div class="fixed inset-0 bg-black/50" on:click={() => (showHashModal = false)}></div>
			<div class="relative z-50 m-4 w-full max-w-lg rounded-lg bg-white p-6">
				<h3 class="mb-4 text-lg font-medium">Hash</h3>
				<div class="mb-4 break-all rounded bg-gray-100 p-3 font-mono text-sm">
					{hash}
				</div>
				<div class="flex justify-end gap-2">
					<Button variant="outline" on:click={() => (showHashModal = false)}>Close</Button>
					<Button
						variant="default"
						on:click={async () => {
							if (hash) {
								// sprawdzamy czy hash istnieje
								try {
									await navigator.clipboard.writeText(hash);
									notifications.add('Hash copied to clipboard', 'success');
									showHashModal = false;
								} catch (e) {
									notifications.add('Failed to copy hash', 'error');
								}
							}
						}}
					>
						Copy to Clipboard
					</Button>
				</div>
			</div>
		</div>
	{/if}
</div>
