<script lang="ts">
	import { onMount } from 'svelte';
	import { get } from 'svelte/store';
	import {
		client,
		currentSniffer,
		isLoading,
		notifications,
		activeSnifferId,
		availableNetworks
	} from '../stores';
	import { Button } from './ui/button';
	import type { SnifferInfo, Recording } from '../proto/service';

	let activeSniffers: SnifferInfo[] = [];
	let initialized = false;
	let networkInterfaces: string[] = [];
	let recordings: Recording[] = [];
	let selectedSource: 'interface' | 'file' = 'interface';
	let selectedInterface: string = '';
	let selectedRecording: string = '';

	async function initialize() {
		try {
			await Promise.all([loadSniffers(), loadNetworkInterfaces(), loadRecordings()]);
			initialized = true;
		} catch (e) {
			console.error('Initialization error:', e);
			notifications.add('Failed to initialize', 'error');
		}
	}

	async function loadNetworkInterfaces() {
		try {
			const currentClient = get(client);
			if (!currentClient) throw new Error('Client not initialized');

			const response = await currentClient.networkInterfaceList({});
			networkInterfaces = response.response.ifaces;
			if (networkInterfaces.length > 0) {
				selectedInterface = networkInterfaces[0];
			}
		} catch (e) {
			console.error('Failed to load network interfaces:', e);
			notifications.add('Failed to load network interfaces', 'error');
		}
	}

	async function loadRecordings() {
		try {
			const currentClient = get(client);
			if (!currentClient) throw new Error('Client not initialized');

			const response = await currentClient.recordingList({
				allowedTypes: [1, 2] // RADIOTAP and RAW80211
			});
			recordings = response.response.recordings;
			if (recordings.length > 0) {
				selectedRecording = recordings[0].uuid;
			}
		} catch (e) {
			console.error('Failed to load recordings:', e);
			notifications.add('Failed to load recordings', 'error');
		}
	}

	async function loadSniffers() {
		try {
			const currentClient = get(client);
			if (!currentClient) throw new Error('Client not initialized');

			isLoading.set(true);
			const response = await currentClient.snifferList({});
			console.log('Loaded sniffers:', response.response.sniffers);
			activeSniffers = response.response.sniffers;

			if (activeSniffers.length > 0) {
				selectSniffer(activeSniffers[0]);
			} else {
				currentSniffer.set(null);
				activeSnifferId.set(null);
			}
		} catch (e) {
			console.error('Failed to load sniffers:', e);
			notifications.add('Failed to load active sniffers', 'error');
		} finally {
			isLoading.set(false);
		}
	}

	async function createSniffer() {
		try {
			const currentClient = get(client);
			if (!currentClient) throw new Error('Client not initialized');

			if (selectedSource === 'file' && !selectedRecording) {
				notifications.add('Please select a recording file', 'error');
				return;
			}

			if (selectedSource === 'interface' && !selectedInterface) {
				notifications.add('Please select a network interface', 'error');
				return;
			}

			isLoading.set(true);
			const response = await currentClient.snifferCreate({
				isFileBased: selectedSource === 'file',
				netIfaceName: selectedSource === 'interface' ? selectedInterface : '',
				recordingUuid: selectedSource === 'file' ? selectedRecording : ''
			});

			console.log('Sniffer created:', response.response);

			await loadSniffers();

			// Auto refreshing AccessPointList
			const newSnifferId = response.response.snifferUuid;
			if (newSnifferId) {
				const networksResponse = await currentClient.accessPointList({
					snifferUuid: newSnifferId
				});
				availableNetworks.set(networksResponse.response.nets);
			}
		} catch (e) {
			console.error('Failed to create sniffer:', e);
			notifications.add('Failed to create sniffer', 'error');
		} finally {
			isLoading.set(false);
		}
	}

	async function destroySniffer(uuid: string) {
		try {
			const currentClient = get(client);
			if (!currentClient) throw new Error('Client not initialized');

			isLoading.set(true);
			await currentClient.snifferDestroy({ snifferUuid: uuid });
			console.log('Sniffer destroyed, reloading list...');

			if (get(activeSnifferId) === uuid) {
				currentSniffer.set(null);
				activeSnifferId.set(null);
				availableNetworks.set([]);
			}

			await loadSniffers();
		} catch (e) {
			console.error('Failed to destroy sniffer:', e);
			notifications.add('Failed to destroy sniffer', 'error');
		} finally {
			isLoading.set(false);
		}
	}

	function selectSniffer(sniffer: SnifferInfo) {
		currentSniffer.set(sniffer);
		activeSnifferId.set(sniffer.uuid);

		// Load networks for selected sniffer
		const currentClient = get(client);
		if (currentClient) {
			currentClient
				.accessPointList({ snifferUuid: sniffer.uuid })
				.then((response) => availableNetworks.set(response.response.nets))
				.catch((e) => {
					console.error('Failed to load networks:', e);
					notifications.add('Failed to load networks', 'error');
				});
		}
	}

	$: if ($client && !initialized) {
		console.log('Client initialized, loading data...');
		initialize();
	}

	onMount(() => {
		if ($client && !initialized) {
			console.log('Client available on mount, loading data...');
			initialize();
		}
	});

	function getSnifferDisplayName(sniffer: SnifferInfo): string {
		if (sniffer.isFileBased) {
			return `File: ${sniffer.filename}`;
		}
		return `Interface: ${sniffer.netIfaceName}`;
	}

	function getRecordingDisplayName(recording: Recording): string {
		return recording.displayName || recording.filename || `Recording ${recording.uuid.slice(0, 8)}`;
	}
</script>

<div class="space-y-4">
	<div class="bg-card text-card-foreground rounded-lg p-4 shadow">
		<h2 class="mb-4 text-lg font-semibold">Sniffer Management</h2>

		{#if !initialized}
			<div class="py-4 text-center">
				<p class="text-muted-foreground">Initializing...</p>
			</div>
		{:else}
			<div class="space-y-4">
				<div class="flex space-x-4">
					<label class="flex items-center space-x-2">
						<input type="radio" bind:group={selectedSource} value="interface" class="h-4 w-4" />
						<span>Network Interface</span>
					</label>
					<label class="flex items-center space-x-2">
						<input type="radio" bind:group={selectedSource} value="file" class="h-4 w-4" />
						<span>Recording File</span>
					</label>
				</div>

				{#if selectedSource === 'interface'}
					<div class="space-y-2">
						<label class="block text-sm font-medium">Network Interface</label>
						<select
							bind:value={selectedInterface}
							class="w-full rounded-md border p-2"
							disabled={networkInterfaces.length === 0}
						>
							{#if networkInterfaces.length === 0}
								<option value="">No interfaces available</option>
							{:else}
								{#each networkInterfaces as iface}
									<option value={iface}>{iface}</option>
								{/each}
							{/if}
						</select>
					</div>
				{:else}
					<div class="space-y-2">
						<label class="block text-sm font-medium">Recording File</label>
						<select
							bind:value={selectedRecording}
							class="w-full rounded-md border p-2"
							disabled={recordings.length === 0}
						>
							{#if recordings.length === 0}
								<option value="">No recordings available</option>
							{:else}
								{#each recordings as recording}
									<option value={recording.uuid}>
										{getRecordingDisplayName(recording)}
									</option>
								{/each}
							{/if}
						</select>
					</div>
				{/if}

				<Button
					on:click={createSniffer}
					disabled={$isLoading ||
						(selectedSource === 'interface' && !selectedInterface) ||
						(selectedSource === 'file' && !selectedRecording)}
					variant="default"
					class="w-full"
				>
					Create Sniffer
				</Button>
			</div>

			<div class="mt-6">
				<h3 class="text-md text-foreground mb-2 font-medium">Active Sniffers</h3>
				{#if activeSniffers.length === 0}
					<p class="text-muted-foreground text-sm">No active sniffers</p>
				{:else}
					<div class="divide-border border-border divide-y rounded-lg">
						{#each activeSniffers as sniffer}
							<div class="flex items-center justify-between p-3">
								<div class="min-w-0 flex-1 space-y-1">
									<div class="flex items-center space-x-2">
										<input
											type="radio"
											name="active-sniffer"
											value={sniffer.uuid}
											checked={$activeSnifferId === sniffer.uuid}
											on:change={() => selectSniffer(sniffer)}
											class="h-4 w-4"
										/>
										<div class="flex flex-col">
											<span class="text-foreground text-sm font-medium">
												{getSnifferDisplayName(sniffer)}
											</span>
											<span class="text-muted-foreground text-sm">
												Type: {sniffer.isFileBased ? 'File Based' : 'Network'}
											</span>
										</div>
									</div>
								</div>
								<Button
									on:click={() => destroySniffer(sniffer.uuid)}
									variant="destructive"
									size="sm"
									disabled={$isLoading}
									class="ml-4"
								>
									Destroy
								</Button>
							</div>
						{/each}
					</div>
				{/if}
			</div>
		{/if}
	</div>
</div>
