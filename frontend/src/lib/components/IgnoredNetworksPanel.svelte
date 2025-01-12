<script lang="ts">
    import { onMount } from 'svelte';
    import { get } from 'svelte/store';
    import { 
        client, 
        activeSnifferId,
        error,
        isLoading
    } from '../stores';
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
            error.set(e instanceof Error ? e.message : 'Failed to load ignored networks');
        } finally {
            isLoading.set(false);
        }
    }

    // Ładuj listę przy montowaniu komponentu
    onMount(loadIgnoredNetworks);

    // Ładuj też listę gdy zmieni się aktywny sniffer
    $: if ($activeSnifferId) {
        loadIgnoredNetworks();
    }
</script>

<div class="bg-white p-4 rounded-lg shadow">
    <div class="flex justify-between items-center mb-4">
        <h2 class="text-lg font-semibold">Ignored Networks</h2>
        <Button
            variant="outline"
            size="sm"
            on:click={loadIgnoredNetworks}
            disabled={$isLoading}
        >
            Refresh
        </Button>
    </div>

    {#if $isLoading}
        <div class="flex justify-center items-center h-32">
            <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900"></div>
        </div>
    {:else if ignoredNetworks.length === 0}
        <p class="text-gray-500 text-center py-8">
            No ignored networks
        </p>
    {:else}
        <div class="space-y-2">
            {#each ignoredNetworks as network}
                <div class="border rounded-lg p-3">
                    <p class="font-medium">
                        {network.ssid || 'Hidden Network'}
                    </p>
                    <p class="text-sm text-gray-500 font-mono">
                        {network.bssid}
                    </p>
                </div>
            {/each}
        </div>
    {/if}
</div>