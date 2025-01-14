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
	import type { SnifferInfo } from '../proto/service';

	let activeSniffers: SnifferInfo[] = [];
	let initialized = false;

	async function initialize() {
		try {
			await loadSniffers();
			initialized = true;
		} catch (e) {
			console.error('Initialization error:', e);
			notifications.add('Failed to initialize', 'error');
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
				currentSniffer.set(activeSniffers[0]);
				activeSnifferId.set(activeSniffers[0].uuid);
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

			isLoading.set(true);
			const response = await currentClient.snifferCreate({
				isFileBased: false,
				netIfaceName: 'wlan0',
				recordingUuid: ''
			});

			console.log('Sniffer created:', response.response);

			await new Promise((resolve) => setTimeout(resolve, 500));
			await loadSniffers();

			// Auto refreshing AccessPointList
			const newSnifferId = get(activeSnifferId);
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

			// Resetting stores
			currentSniffer.set(null);
			activeSnifferId.set(null);
			availableNetworks.set([]);

			await new Promise((resolve) => setTimeout(resolve, 500));
			await loadSniffers();
		} catch (e) {
			console.error('Failed to destroy sniffer:', e);
			notifications.add('Failed to destroy sniffer', 'error');
		} finally {
			isLoading.set(false);
		}
	}

	// Client changes subscribtion
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
			return sniffer.filename;
		}
		return sniffer.netIfaceName;
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
			<Button
				on:click={createSniffer}
				disabled={$isLoading || activeSniffers.length > 0}
				variant="default"
				class="mb-4 w-full"
			>
				Create Sniffer
			</Button>

			<div class="mt-4">
				<h3 class="text-md text-foreground mb-2 font-medium">Active Sniffers</h3>
				{#if activeSniffers.length === 0}
					<p class="text-muted-foreground text-sm">No active sniffers</p>
				{:else}
					<div class="divide-border border-border divide-y rounded-lg">
						{#each activeSniffers as sniffer}
							<div class="flex items-center justify-between p-3">
								<div class="min-w-0 flex-1 space-y-1">
									<div class="text-foreground truncate text-sm font-medium">
										{getSnifferDisplayName(sniffer)}
									</div>
									<div class="text-muted-foreground text-sm">
										Type: {sniffer.isFileBased ? 'File Based' : 'Network'}
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
