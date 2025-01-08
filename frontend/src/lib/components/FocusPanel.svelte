<script lang="ts">
    import { onMount } from 'svelte';
    import { get } from 'svelte/store';
    import { 
        client, 
        activeSnifferId, 
        selectedNetwork, 
        error,
        isLoading
    } from '../stores';
    import { Button } from './ui/button';
    import { Card, CardContent, CardHeader, CardTitle } from './ui/card';

    let focusedNetwork: { bssid: string; ssid: string } | null = null;
    let focusedChannel: number | null = null;

    async function checkActiveFocus() {
        try {
            const currentClient = get(client);
            const snifferId = get(activeSnifferId);

            if (!currentClient || !snifferId) {
                return;
            }

            const response = await currentClient.focusGetActive({
                snifferUuid: snifferId
            });

            if (response.response.bssid) {
                focusedNetwork = {
                    bssid: response.response.bssid,
                    ssid: response.response.ssid
                };
                focusedChannel = response.response.channel;
            }
        } catch (e) {
            console.error('Failed to check active focus:', e);
            error.set(e instanceof Error ? e.message : 'Failed to check active focus');
        }
    }

    async function startFocus() {
        try {
            const currentClient = get(client);
            const snifferId = get(activeSnifferId);
            const network = get(selectedNetwork);

            if (!currentClient || !snifferId || !network) {
                throw new Error('Missing required configuration for focus');
            }

            isLoading.set(true);

            const response = await currentClient.focusStart({
                snifferUuid: snifferId,
                bssid: network.bssid
            });

            focusedNetwork = network;
            focusedChannel = response.response.channel;
        } catch (e) {
            console.error('Failed to start focus:', e);
            error.set(e instanceof Error ? e.message : 'Failed to start focus');
        } finally {
            isLoading.set(false);
        }
    }

    async function stopFocus() {
        try {
            const currentClient = get(client);
            const snifferId = get(activeSnifferId);

            if (!currentClient || !snifferId) {
                throw new Error('Missing required configuration for focus');
            }

            isLoading.set(true);

            await currentClient.focusStop({
                snifferUuid: snifferId
            });

            focusedNetwork = null;
            focusedChannel = null;
        } catch (e) {
            console.error('Failed to stop focus:', e);
            error.set(e instanceof Error ? e.message : 'Failed to stop focus');
        } finally {
            isLoading.set(false);
        }
    }

    onMount(checkActiveFocus);

    $: selectedNet = $selectedNetwork;
</script>

<Card>
    <CardHeader>
        <CardTitle>Channel Focus</CardTitle>
    </CardHeader>
    <CardContent>
        {#if focusedNetwork}
            <div class="space-y-4">
                <div>
                    <p class="text-sm font-medium">Currently focused on:</p>
                    <p class="text-sm">{focusedNetwork.ssid || 'Hidden Network'}</p>
                    <p class="text-xs text-gray-500">{focusedNetwork.bssid}</p>
                    {#if focusedChannel}
                        <p class="text-sm mt-1">Channel: {focusedChannel}</p>
                    {/if}
                </div>
                <Button
                    on:click={stopFocus}
                    variant="destructive"
                    disabled={!$activeSnifferId}
                    class="w-full"
                >
                    Stop Focus
                </Button>
            </div>
        {:else}
            <div class="space-y-4">
                <p class="text-sm text-gray-500">
                    {selectedNet 
                        ? 'Start focusing on the selected network to capture traffic more effectively.'
                        : 'Select a network to begin focusing.'}
                </p>
                <Button
                    on:click={startFocus}
                    disabled={!selectedNet || !$activeSnifferId}
                    class="w-full"
                >
                    Start Focus
                </Button>
            </div>
        {/if}
    </CardContent>
</Card>