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
    import { Input } from "./ui/input";
    import type { BasicNetworkInfo } from '../proto/service';

    let networks: BasicNetworkInfo[] = [];
    let showPasswordDialog = false;
    let selectedNetworkForPassword: BasicNetworkInfo | null = null;
    let password = '';
    let showDetailsModal = false;
    let selectedBssid = '';

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

    async function submitPassword() {
        if (!selectedNetworkForPassword) return;

        try {
            const currentClient = get(client);
            const snifferId = get(activeSnifferId);
            
            if (!currentClient || !snifferId) {
                throw new Error('Client or sniffer not initialized');
            }

            isLoading.set(true);
            const response = await currentClient.accessPointProvidePassword({
                snifferUuid: snifferId,
                bssid: selectedNetworkForPassword.bssid,
                password: password
            });

            console.log('Password response:', response);
            
            if (response.response.state === 0) { // DECRYPTED
                selectedNetwork.set(selectedNetworkForPassword);
                showPasswordDialog = false;
                password = '';
            } else {
                error.set('Invalid password');
            }
        } catch (e) {
            console.error('Password submission error:', e);
            error.set(e instanceof Error ? e.message : 'Failed to submit password');
        } finally {
            isLoading.set(false);
        }
    }

    onMount(async () => {
        if ($activeSnifferId) {
            await refreshNetworks();
        }
    });

    function handleNetworkSelect(network: BasicNetworkInfo) {
    console.log('Network clicked:', network.bssid);
    console.log('Currently selected:', $selectedNetwork?.bssid);
    
    if ($selectedNetwork?.bssid === network.bssid) {
        console.log('Opening details modal');
        selectedBssid = network.bssid;
        showDetailsModal = true;
    } else {
        console.log('Opening password dialog');
        selectedNetworkForPassword = network;
        showPasswordDialog = true;
    }
}
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
            <div class="space-y-2">
                {#each networks as network}
                <div 
                class="p-3 border rounded cursor-pointer transition-colors
                       {$selectedNetwork?.bssid === network.bssid ? 'border-blue-500 bg-blue-50' : 'border-gray-200 hover:bg-gray-50'}"
                on:click={() => handleNetworkSelect(network)}>
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
<NetworkDetailsModal
    show={showDetailsModal}
    bssid={selectedBssid}
    onClose={() => showDetailsModal = false}
/>
<!-- Password Dialog -->
{#if showPasswordDialog}
<div class="fixed inset-0 z-50">
    <!-- Overlay -->
    <div class="fixed inset-0 bg-black/50" />
    
    <!-- Dialog -->
    <div class="fixed inset-0 flex items-center justify-center">
        <div class="bg-white rounded-lg shadow-xl w-full max-w-md mx-4">
            <div class="p-6">
                <h3 class="text-lg font-semibold mb-4">
                    Enter Password for {selectedNetworkForPassword?.ssid || 'Network'}
                </h3>
                
                <div class="space-y-4">
                    <Input
                        type="password"
                        bind:value={password}
                        placeholder="Network password"
                    />
                    
                    <div class="flex justify-end gap-2">
                        <Button
                            variant="outline"
                            on:click={() => {
                                showPasswordDialog = false;
                                password = '';
                            }}
                        >
                            Cancel
                        </Button>
                        <Button
                            variant="default"
                            on:click={submitPassword}
                        >
                            Submit
                        </Button>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{/if}