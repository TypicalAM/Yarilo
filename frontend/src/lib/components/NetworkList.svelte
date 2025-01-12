<script lang="ts">
    import { onMount } from 'svelte';
    import { get } from 'svelte/store';
    import { 
        client, 
        selectedNetwork, 
        availableNetworks, 
        activeSnifferId,
        error,
        isLoading
    } from '../stores';
    import NetworkDetailsModal from './NetworkDetailsModal.svelte';
    import { Button } from "./ui/button";
    import type { BasicNetworkInfo } from '../proto/service';  // Dodany import

    let networks: BasicNetworkInfo[] = [];
    let showDetailsModal = false;
    let selectedBssid: string | null = null;

    // Subskrybuj zmiany w availableNetworks store
    $: {
        networks = $availableNetworks;
        console.log('Networks updated:', networks);
    }

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
            console.log('Networks loaded:', networks);
        } catch (e) {
            console.error('Failed to refresh networks:', e);
            error.set(e instanceof Error ? e.message : 'Failed to refresh networks');
        } finally {
            isLoading.set(false);
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
</script>

<div class="bg-white rounded-lg shadow">
    <div class="p-4">
        <div class="flex justify-between items-center mb-4">
            <h2 class="text-lg font-semibold">Available Networks</h2>
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
            <p class="text-gray-500">Loading networks...</p>
        {:else if networks.length === 0}
            <p class="text-gray-500">No networks found</p>
        {:else}
            <div class="space-y-2 max-h-96 overflow-y-auto">
                {#each networks as network}
                    <div 
                        class="p-3 border rounded cursor-pointer transition-colors
                               {$selectedNetwork?.bssid === network.bssid ? 'border-blue-500 bg-blue-50' : 'border-gray-200 hover:bg-gray-50'}"
                        on:click={() => handleNetworkSelect(network)}
                    >
                        <div class="flex justify-between items-center">
                            <div>
                                <h3 class="font-medium">{network.ssid || 'Hidden Network'}</h3>
                                <p class="text-sm text-gray-500">{network.bssid}</p>
                            </div>
                            {#if $selectedNetwork?.bssid === network.bssid}
                                <div class="text-blue-500">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                                        <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
                                    </svg>
                                </div>
                            {/if}
                        </div>
                    </div>
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
    />
{/if}