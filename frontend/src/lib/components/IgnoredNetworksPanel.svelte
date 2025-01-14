<script lang="ts">
	import { onMount } from 'svelte';
	import { get } from 'svelte/store';
	import { client, activeSnifferId, notifications, isLoading } from '../stores';
	import type { BasicNetworkInfo } from '../proto/service';
	import { Button } from './ui/button';

	let ignoredNetworks: BasicNetworkInfo[] = [];

	async function loadIgnoredNetworks() {
		try {
			const currentClient = get(client);
			const snifferId = get(activeSnifferId);

			if (!currentClient || !snifferId) {
				throw new Error('Client or sniffer not initialized');
			}

			isLoading.set(true);
			const response = await currentClient.accessPointListIgnored({
				snifferUuid: snifferId
			});

			ignoredNetworks = response.response.nets;
		} catch (e) {
			console.error('Failed to load ignored networks:', e);
			notifications.add('Failed to load ignored networks', 'error');
		} finally {
			isLoading.set(false);
		}
	}

	onMount(loadIgnoredNetworks);

	$: if ($activeSnifferId) {
		loadIgnoredNetworks();
	}
</script>

<div class="rounded-lg bg-white p-4 shadow">
	<div class="mb-4 flex items-center justify-between">
		<h2 class="text-lg font-semibold">Ignored Networks</h2>
		<Button variant="outline" size="sm" on:click={loadIgnoredNetworks} disabled={$isLoading}>
			Refresh
		</Button>
	</div>

	{#if $isLoading}
		<div class="flex h-32 items-center justify-center">
			<div class="h-8 w-8 animate-spin rounded-full border-b-2 border-gray-900"></div>
		</div>
	{:else if ignoredNetworks.length === 0}
		<p class="py-8 text-center text-gray-500">No ignored networks</p>
	{:else}
		<div class="space-y-2">
			{#each ignoredNetworks as network}
				<div class="rounded-lg border p-3">
					<p class="font-medium">
						{network.ssid || 'Hidden Network'}
					</p>
					<p class="font-mono text-sm text-gray-500">
						{network.bssid}
					</p>
				</div>
			{/each}
		</div>
	{/if}
</div>
