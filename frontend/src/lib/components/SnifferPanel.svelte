<script lang="ts">
    import { onMount } from 'svelte';
    import { get } from 'svelte/store';
    import { 
        client, 
        currentSniffer,
        isLoading,
        error,
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
            error.set(e instanceof Error ? e.message : 'Failed to initialize');
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
            error.set(e instanceof Error ? e.message : 'Failed to load active sniffers');
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
                netIfaceName: "wlan0",
                recordingUuid: ""
            });

            console.log('Sniffer created:', response.response);
            
            // Poczekaj chwilę przed załadowaniem listy
            await new Promise(resolve => setTimeout(resolve, 500));
            await loadSniffers();
            
            // Automatycznie odśwież listę sieci
            const newSnifferId = get(activeSnifferId);
            if (newSnifferId) {
                const networksResponse = await currentClient.accessPointList({ 
                    snifferUuid: newSnifferId 
                });
                availableNetworks.set(networksResponse.response.nets);
            }
        } catch (e) {
            console.error('Failed to create sniffer:', e);
            error.set(e instanceof Error ? e.message : 'Failed to create sniffer');
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
            
            // Reset wszystkich powiązanych store'ów
            currentSniffer.set(null);
            activeSnifferId.set(null);
            availableNetworks.set([]);
            
            // Poczekaj chwilę przed załadowaniem listy
            await new Promise(resolve => setTimeout(resolve, 500));
            await loadSniffers();
            
        } catch (e) {
            console.error('Failed to destroy sniffer:', e);
            error.set(e instanceof Error ? e.message : 'Failed to destroy sniffer');
        } finally {
            isLoading.set(false);
        }
    }

    // Subskrybuj zmiany klienta
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
    <div class="p-4 bg-card text-card-foreground rounded-lg shadow">
        <h2 class="text-lg font-semibold mb-4">Sniffer Management</h2>

        {#if !initialized}
            <div class="text-center py-4">
                <p class="text-muted-foreground">Initializing...</p>
            </div>
        {:else}
            <Button
                on:click={createSniffer}
                disabled={$isLoading || activeSniffers.length > 0}
                variant="default"
                class="w-full mb-4"
            >
                Create Sniffer
            </Button>

            <div class="mt-4">
                <h3 class="text-md font-medium mb-2 text-foreground">Active Sniffers</h3>
                {#if activeSniffers.length === 0}
                    <p class="text-muted-foreground text-sm">No active sniffers</p>
                {:else}
                    <div class="divide-y divide-border border-border rounded-lg">
                        {#each activeSniffers as sniffer}
                            <div class="p-3 flex items-center justify-between">
                                <div class="space-y-1 flex-1 min-w-0"> <!-- dodane flex-1 i min-w-0 -->
                                    <div class="font-medium text-sm text-foreground truncate"> <!-- dodane truncate -->
                                        {getSnifferDisplayName(sniffer)}
                                    </div>
                                    <div class="text-sm text-muted-foreground">
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