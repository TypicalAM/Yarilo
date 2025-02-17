<script lang="ts">
	import { onMount } from 'svelte';
	import { get } from 'svelte/store';
	import { writable } from 'svelte/store';
	import {
		client,
		selectedNetwork,
		availableNetworks,
		activeSnifferId,
		notifications,
		isLoading
	} from '../stores';
	import NetworkDetailsModal from './NetworkDetailsModal.svelte';
	import { ignoredNetworksUpdated } from '../stores';
	import { Button } from './ui/button';
	import type { BasicNetworkInfo } from '../proto/service';

	$: if ($ignoredNetworksUpdated) {
		refreshNetworks();
		ignoredNetworksUpdated.set(false);
	}

	interface GroupedNetwork {
		ssid: string;
		instances: BasicNetworkInfo[];
	}

	const expandedGroups = writable<Set<string>>(new Set());
	const focusedBssid = writable<string | null>(null);

	let networks: BasicNetworkInfo[] = [];
	let showDetailsModal = false;
	let selectedBssid: string | null = null;
	let groupedNetworks: GroupedNetwork[] = [];

	async function refreshNetworks() {
		try {
			const currentClient = get(client);
			const snifferId = get(activeSnifferId);

			if (!currentClient || !snifferId) {
				throw new Error('Client or sniffer not initialized');
			}

			isLoading.set(true);
			const response = await currentClient.accessPointList({
				snifferUuid: snifferId
			});

			networks = response.response.nets;
			availableNetworks.set(networks);
			await checkFocusStatus(); // Najpierw sprawdzamy focus
			groupedNetworks = sortNetworks(groupNetworks(networks)); // Potem sortujemy
			console.log('Networks loaded:', networks);
		} catch (e) {
			console.error('Failed to refresh networks:', e);
			notifications.add('Failed to refresh networks', 'error');
		} finally {
			isLoading.set(false);
		}
	}

	async function checkFocusStatus() {
		const currentClient = get(client);
		const snifferId = get(activeSnifferId);

		if (!currentClient || !snifferId) return;

		try {
			const response = await currentClient.focusGetActive({
				snifferUuid: snifferId
			});
			focusedBssid.set(response.response.bssid);
		} catch (e) {
			console.error('Failed to check focus status:', e);
			focusedBssid.set(null);
		}
	}

	function handleNetworkSelect(network: BasicNetworkInfo) {
		selectedBssid = network.bssid;
		showDetailsModal = true;
	}

	onMount(async () => {
		if ($activeSnifferId) {
			await refreshNetworks();
		}
	});

	function sortNetworks(networks: GroupedNetwork[]): GroupedNetwork[] {
		return networks.sort((a, b) => {
			const aFocused = a.instances.some((inst) => inst.bssid === $focusedBssid);
			const bFocused = b.instances.some((inst) => inst.bssid === $focusedBssid);

			if (aFocused && !bFocused) return -1;
			if (!aFocused && bFocused) return 1;
			return a.ssid.localeCompare(b.ssid);
		});
	}

	function groupNetworks(networks: BasicNetworkInfo[]): GroupedNetwork[] {
		const grouped = networks.reduce(
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
			{} as Record<string, GroupedNetwork>
		);

		return Object.values(grouped);
	}

	function toggleGroup(ssid: string) {
		expandedGroups.update((expanded) => {
			const newExpanded = new Set(expanded);
			if (newExpanded.has(ssid)) {
				newExpanded.delete(ssid);
			} else {
				newExpanded.add(ssid);
			}
			return newExpanded;
		});
	}

	$: {
		networks = $availableNetworks;
		groupedNetworks = sortNetworks(groupNetworks(networks));
		console.log('Networks grouped:', groupedNetworks);
	}
</script>

<div class="bg-background border-border rounded-lg border shadow">
	<div class="p-4">
		<div class="mb-4 flex items-center justify-between">
			<h2 class="text-foreground text-lg font-semibold">Available Networks</h2>
			<Button
				on:click={refreshNetworks}
				disabled={$isLoading || !$activeSnifferId}
				variant="outline"
				size="sm"
			>
				Refresh Networks
			</Button>
		</div>

		{#if $isLoading}
			<p class="text-muted-foreground">Loading networks...</p>
		{:else if networks.length === 0}
			<p class="text-muted-foreground">No networks found</p>
		{:else}
			<div class="max-h-96 space-y-2 overflow-y-auto">
				{#each groupedNetworks as group}
					{#if group.instances.length > 1}
						<!-- Group ESS -->
						<div
							class="rounded border transition-colors {group.instances.some(
								(inst) => inst.bssid === $focusedBssid
							)
								? 'border-green-500 bg-green-50/50 dark:border-green-400 dark:bg-green-900/20'
								: 'border-border'}"
						>
							<div
								class="hover:bg-muted/50 flex cursor-pointer items-center justify-between p-3"
								on:click={() => toggleGroup(group.ssid)}
							>
								<div>
									<div class="flex items-center gap-2">
										<h3 class="text-foreground font-medium">{group.ssid}</h3>
										{#if group.instances.some((inst) => inst.bssid === $focusedBssid)}
											<span
												class="rounded-full bg-green-100 px-2 py-1 text-xs text-green-800 dark:bg-green-900 dark:text-green-200"
											>
												Focused
											</span>
										{/if}
									</div>
									<p class="text-muted-foreground text-sm">
										{group.instances.length} Access Points
									</p>
								</div>
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
							</div>

							{#if $expandedGroups.has(group.ssid)}
								<div class="border-border bg-muted/50 border-t">
									{#each group.instances as instance}
										<div
											class="border-border cursor-pointer border-b p-3 last:border-b-0
                							{instance.bssid === $focusedBssid
												? 'bg-green-100/50 hover:bg-green-100 dark:bg-green-900/30 dark:hover:bg-green-900/40'
												: $selectedNetwork?.bssid === instance.bssid
													? 'bg-blue-100/50 hover:bg-blue-100 dark:bg-blue-900/30 dark:hover:bg-blue-900/40'
													: 'hover:bg-muted'}"
											on:click={() => handleNetworkSelect(instance)}
										>
											<div class="flex items-center justify-between">
												<div class="flex items-center gap-2">
													<p class="text-foreground font-mono text-sm">{instance.bssid}</p>
													{#if instance.bssid === $focusedBssid}
														<span
															class="rounded-full bg-green-100 px-2 py-1 text-xs text-green-800 dark:bg-green-900 dark:text-green-200"
														>
															Focused
														</span>
													{/if}
												</div>
												{#if $selectedNetwork?.bssid === instance.bssid}
													<div class="text-blue-500">
														<svg
															xmlns="http://www.w3.org/2000/svg"
															class="h-4 w-4"
															viewBox="0 0 20 20"
															fill="currentColor"
														>
															<path
																fill-rule="evenodd"
																d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
																clip-rule="evenodd"
															/>
														</svg>
													</div>
												{/if}
											</div>
										</div>
									{/each}
								</div>
							{/if}
						</div>
					{:else}
						<!-- Single network -->
						<div
							class="cursor-pointer rounded border p-3 transition-colors
							{$selectedNetwork?.bssid === group.instances[0].bssid
								? 'border-blue-500 bg-blue-50 dark:border-blue-400 dark:bg-blue-900/20'
								: 'border-border hover:bg-muted'}
							{group.instances[0].bssid === $focusedBssid
								? 'border-green-500 bg-green-50 dark:border-green-400 dark:bg-green-900/20'
								: ''}"
							on:click={() => handleNetworkSelect(group.instances[0])}
						>
							<div class="flex items-center justify-between">
								<div>
									<div class="flex items-center gap-2">
										<h3 class="text-foreground font-medium">{group.ssid}</h3>
										{#if group.instances[0].bssid === $focusedBssid}
											<span
												class="rounded-full bg-green-100 px-2 py-1 text-xs text-green-800 dark:bg-green-900 dark:text-green-200"
											>
												Focused
											</span>
										{/if}
									</div>
									<p class="text-muted-foreground font-mono text-sm">{group.instances[0].bssid}</p>
								</div>
								{#if $selectedNetwork?.bssid === group.instances[0].bssid}
									<div class="text-blue-500 dark:text-blue-400">
										<svg
											xmlns="http://www.w3.org/2000/svg"
											class="h-5 w-5"
											viewBox="0 0 20 20"
											fill="currentColor"
										>
											<path
												fill-rule="evenodd"
												d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
												clip-rule="evenodd"
											/>
										</svg>
									</div>
								{/if}
							</div>
						</div>
					{/if}
				{/each}
			</div>
		{/if}
	</div>
</div>

{#if showDetailsModal && selectedBssid}
	<NetworkDetailsModal
		show={true}
		bssid={selectedBssid}
		onClose={() => {
			showDetailsModal = false;
			selectedBssid = null;
		}}
		onFocusChange={refreshNetworks}
	/>
{/if}
