<script lang="ts">
	import { Button } from './ui/button';
	import type { Recording } from '../proto/service';
	import type { RpcError, ServerStreamingCall } from '@protobuf-ts/runtime-rpc';
	import type { Packet, RecordingLoadDecryptedRequest } from '../proto/service';
	import { client, notifications, isLoading, packets } from '../stores';
	import { get } from 'svelte/store';

	export let show = false;
	export let onClose = () => {};

	let recordings: Recording[] = [];

	async function loadRecordings() {
		try {
			const currentClient = get(client);
			if (!currentClient) {
				throw new Error('Client not initialized');
			}

			isLoading.set(true);

			console.log('Requesting recordings list...');

			const response = await currentClient.recordingList({
				allowedTypes: [3]
			});
			console.log('Raw response:', response);
			console.log('Response recordings:', JSON.stringify(response.response.recordings, null, 2));
			recordings = response.response.recordings;
			console.log('Parsed recordings array:', JSON.stringify(recordings, null, 2));

			if (recordings.length === 0) {
				notifications.add('No recordings available', 'error');
			}
		} catch (e) {
			console.error('Failed to load recordings:', e);
			notifications.add('Failed to load recordings list', 'error');
		} finally {
			isLoading.set(false);
		}
	}

	async function loadRecording(recording: Recording) {
		try {
			const currentClient = get(client);
			if (!currentClient) {
				throw new Error('Client not initialized');
			}

			isLoading.set(true);

			console.log('Attempting to load recording:', {
				uuid: recording.uuid,
				filename: recording.filename,
				displayName: recording.displayName
			});

			packets.set([]);

			const request = {
				uuid: recording.uuid,
				includePayload: true
			};

			console.log('Sending load request:', request);

			const call: ServerStreamingCall<RecordingLoadDecryptedRequest, Packet> =
				currentClient.recordingLoadDecrypted(request);

			console.log('Stream obtained, starting to read packets...');

			let packetCount = 0;

			try {
				for await (const packet of call.responses) {
					if (!packet) {
						console.warn('Received null/undefined packet');
						continue;
					}

					packets.update((current) => {
						const updated = [...current, packet];
						if (updated.length > 1000) {
							return updated.slice(-1000);
						}
						return updated;
					});
					packetCount++;

					if (packetCount % 100 === 0) {
						console.log(`Loaded ${packetCount} packets...`);
					}
				}
			} catch (streamError) {
				console.error('Error during stream processing:', streamError);
				throw streamError;
			}

			console.log(`Successfully loaded ${packetCount} packets`);
			notifications.add(`Loaded ${packetCount} packets successfully`, 'success');
			onClose();
		} catch (e) {
			console.error('Failed to load recording:', e);

			const rpcError = e as RpcError;
			notifications.add('Failed to load recording', 'error');

			if (rpcError.code) console.error('Error code:', rpcError.code);
		} finally {
			isLoading.set(false);
		}
	}

	$: if (show) {
		loadRecordings();
	}

	function getDataLinkTypeLabel(type: number): string {
		switch (type) {
			case 1:
				return 'RADIOTAP';
			case 2:
				return 'RAW80211';
			case 3:
				return 'ETH2';
			default:
				return 'Unknown';
		}
	}

	function getDisplayName(recording: Recording): string {
		const name = recording.displayName || recording.filename;
		if (!name) return `Recording ${recording.uuid.slice(0, 8)}`;

		// Rozdzielamy nazwę na części: NAZWA_UUID_DATA.pcapng
		const parts = name.split('_');
		if (parts.length >= 2) {
			return parts[0]; // Zwracamy tylko pierwszą część (nazwa nadana przez użytkownika)
		}

		return name;
	}
</script>

<div
	class="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto overflow-x-hidden"
	role="dialog"
	aria-modal="true"
	class:hidden={!show}
>
	<!-- Fading background -->
	<div class="fixed inset-0 bg-black/50" on:click={onClose}></div>

	<!-- Modal contener -->
	<div class="relative z-50 m-4 flex max-h-[80vh] w-full max-w-2xl flex-col rounded-lg bg-white">
		<!-- Header -->
		<div class="flex items-center justify-between border-b p-4">
			<h2 class="text-xl font-semibold">Load Recording</h2>
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

		<div class="flex-1 overflow-y-auto p-6">
			{#if $isLoading}
				<div class="flex h-32 items-center justify-center">
					<div class="border-primary h-8 w-8 animate-spin rounded-full border-b-2"></div>
				</div>
			{:else if recordings.length === 0}
				<p class="text-muted-foreground py-8 text-center">No recordings available</p>
			{:else}
				<div class="space-y-2">
					{#each recordings as recording}
						<div class="border-border hover:bg-muted/50 rounded-lg p-4">
							<div class="flex items-center justify-between">
								<div>
									<p class="text-foreground font-medium">{getDisplayName(recording)}</p>
									<p class="text-muted-foreground text-sm">
										Type: {getDataLinkTypeLabel(recording.datalink)}
									</p>
									<p class="text-muted-foreground font-mono text-xs">{recording.uuid}</p>
								</div>
								<Button
									variant="outline"
									size="sm"
									on:click={() => loadRecording(recording)}
									disabled={$isLoading}
								>
									Load
								</Button>
							</div>
						</div>
					{/each}
				</div>
			{/if}
		</div>
	</div>
</div>
