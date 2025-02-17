<script lang="ts">
	import { onMount } from 'svelte';
	import { get } from 'svelte/store';
	import {
		client,
		activeSnifferId,
		notifications,
		isLoading,
		ignoredNetworksUpdated
	} from '../stores';
	import type { BasicNetworkInfo } from '../proto/service';
	import { Button } from './ui/button';
	import { Input } from './ui/input';
	import { writable } from 'svelte/store';

	interface GroupedIgnoredNetwork {
		ssid: string;
		instances: BasicNetworkInfo[];
	}

	let ignoredNetworks: BasicNetworkInfo[] = [];
	let groupedNetworks: GroupedIgnoredNetwork[] = [];
	let newIdentifier = '';
	let isSSID = false;
	const expandedGroups = writable<Set<string>>(new Set());

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
			groupNetworks();
		} catch (e) {
			console.error('Failed to load ignored networks:', e);
			notifications.add('Failed to load ignored networks', 'error');
		} finally {
			isLoading.set(false);
		}
	}

	async function ignoreNetwork() {
		try {
			const currentClient = get(client);
			const snifferId = get(activeSnifferId);

			if (!currentClient || !snifferId || !newIdentifier.trim()) {
				return;
			}

			isLoading.set(true);
			await currentClient.accessPointIgnore({
				snifferUuid: snifferId,
				bssid: isSSID ? '' : newIdentifier.trim(),
				useSsid: isSSID,
				ssid: isSSID ? newIdentifier.trim() : ''
			});

			notifications.add(`Network ${isSSID ? 'SSID' : 'BSSID'} added to ignore list`, 'success');
			newIdentifier = '';
			await loadIgnoredNetworks();
			ignoredNetworksUpdated.set(true);
		} catch (e) {
			console.error('Failed to ignore network:', e);
			notifications.add('Failed to ignore network', 'error');
		} finally {
			isLoading.set(false);
		}
	}

	function groupNetworks() {
		const grouped = ignoredNetworks.reduce(
			(acc, network) => {
				const ssid = network.ssid || 'Hidden Network';
				if (!acc[ssid]) {
					acc[ssid] = {
						ssid,
						instances: []
					};
				}
				acc[ssid].instances.push(network);
				return acc;
			},
			{} as Record<string, GroupedIgnoredNetwork>
		);

		groupedNetworks = Object.values(grouped).sort((a, b) => a.ssid.localeCompare(b.ssid));
	}

	function toggleGroup(ssid: string) {
		expandedGroups.update((groups) => {
			const newGroups = new Set(groups);
			if (newGroups.has(ssid)) {
				newGroups.delete(ssid);
			} else {
				newGroups.add(ssid);
			}
			return newGroups;
		});
	}

	onMount(loadIgnoredNetworks);

	$: if ($activeSnifferId) {
		loadIgnoredNetworks();
	}
</script>

<div class="bg-background border-border rounded-lg border p-4 shadow">
	<div class="mb-4 flex items-center justify-between">
		<h2 class="text-foreground text-lg font-semibold">Ignored Networks</h2>
		<Button variant="outline" size="sm" on:click={loadIgnoredNetworks} disabled={$isLoading}>
			Refresh
		</Button>
	</div>

	<!-- Add network to ignore -->
	<div class="mb-4 space-y-2">
		<div class="flex items-center space-x-2">
			<Input
				type="text"
				placeholder={isSSID ? 'Enter SSID to ignore' : 'Enter BSSID to ignore'}
				bind:value={newIdentifier}
				class="flex-1"
			/>
			<Button
				variant="default"
				on:click={ignoreNetwork}
				disabled={$isLoading || !newIdentifier.trim()}
			>
				Add
			</Button>
		</div>
		<div class="flex items-center space-x-2">
			<label class="flex items-center space-x-2">
				<input type="radio" bind:group={isSSID} value={false} />
				<span class="text-sm">BSSID</span>
			</label>
			<label class="flex items-center space-x-2">
				<input type="radio" bind:group={isSSID} value={true} />
				<span class="text-sm">SSID</span>
			</label>
		</div>
	</div>

	{#if $isLoading}
		<div class="flex h-32 items-center justify-center">
			<div class="border-primary h-8 w-8 animate-spin rounded-full border-b-2"></div>
		</div>
	{:else if groupedNetworks.length === 0}
		<p class="text-muted-foreground py-8 text-center">No ignored networks</p>
	{:else}
		<div class="max-h-[300px] space-y-2 overflow-y-auto pr-2">
			{#each groupedNetworks as group}
				<div class="border-border rounded-lg border">
					<div
						class="hover:bg-muted flex cursor-pointer items-center justify-between p-3"
						on:click={() => toggleGroup(group.ssid)}
					>
						<div>
							<p class="text-foreground font-medium">{group.ssid}</p>
							<p class="text-muted-foreground text-sm">
								{group.instances.length} Access Point{group.instances.length !== 1 ? 's' : ''}
							</p>
						</div>
						{#if group.instances.length > 1}
							<div
								class="text-gray-400 transition-transform"
								class:rotate-180={$expandedGroups.has(group.ssid)}
							>
								<svg
									xmlns="http://www.w3.org/2000/svg"
									class="h-5 w-5"
									viewBox="0 0 20 20"
									fill="currentColor"
								>
									<path
										d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z"
									/>
								</svg>
							</div>
						{/if}
					</div>
					{#if group.instances.length > 1 && $expandedGroups.has(group.ssid)}
						<div class="border-t bg-gray-50">
							{#each group.instances as instance}
								<div
									class="p-3 last:rounded-b-lg {group.instances.length > 1
										? 'border-b last:border-b-0'
										: ''}"
								>
									<p class="font-mono text-sm text-gray-500">{instance.bssid}</p>
								</div>
							{/each}
						</div>
					{/if}
				</div>
			{/each}
		</div>
	{/if}
</div>
