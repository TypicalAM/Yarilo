<script lang="ts">
    import { fade } from 'svelte/transition';
    import { Button } from "./ui/button";
    import { get } from 'svelte/store';
    import { 
        client, 
        activeSnifferId, 
        error,
        isLoading,
        selectedNetwork 
    } from '../stores';
    import { Input } from './ui/input';
    import type { AccessPointInfo, ClientInfo } from '../proto/service';

    export let show = false;
    export let bssid = '';
    export let onClose = () => {};

    let networkDetails: AccessPointInfo | null = null;
    let isFocused = false;
    let password = '';

    // Notifications handling
    interface Notification {
        message: string;
        type: 'success' | 'error';
        id: number;
    }
    
    let notifications: Notification[] = [];
    let notificationId = 0;

    function addNotification(message: string, type: 'success' | 'error') {
        const id = notificationId++;
        notifications = [...notifications, { message, type, id }];
        setTimeout(() => {
            notifications = notifications.filter(n => n.id !== id);
        }, 3000);
    }

    async function checkFocusStatus() {
        const currentClient = get(client);
        const snifferId = get(activeSnifferId);

        if (!currentClient || !snifferId) return;

        try {
            const response = await currentClient.focusGetActive({
                snifferUuid: snifferId
            });
            isFocused = response.response.bssid === bssid;
        } catch (e) {
            console.error('Failed to check focus status:', e);
        }
    }

    async function toggleFocus() {
        const currentClient = get(client);
        const snifferId = get(activeSnifferId);

        if (!currentClient || !snifferId) {
            addNotification('Client or sniffer not initialized', 'error');
            return;
        }

        try {
            isLoading.set(true);
            if (isFocused) {
                await currentClient.focusStop({
                    snifferUuid: snifferId
                });
                addNotification('Focus stopped', 'success');
            } else {
                await currentClient.focusStart({
                    snifferUuid: snifferId,
                    bssid: bssid
                });
                addNotification('Focus started', 'success');
            }
            isFocused = !isFocused;
        } catch (e) {
            console.error('Focus toggle failed:', e);
            addNotification('Failed to toggle focus', 'error');
        } finally {
            isLoading.set(false);
        }
    }

    // Existing functions modified to use proper client/snifferId access
    async function loadNetworkDetails() {
        const currentClient = get(client);
        const snifferId = get(activeSnifferId);

        if (!currentClient || !snifferId) return;

        try {
            isLoading.set(true);
            const response = await currentClient.accessPointGet({
                snifferUuid: snifferId,
                bssid: bssid
            });

            networkDetails = response.response.ap || null;
            await checkFocusStatus();
        } catch (e) {
            console.error('Failed to load network details:', e);
            error.set(e instanceof Error ? e.message : 'Failed to load network details');
        } finally {
            isLoading.set(false);
        }
    }

    // ... [pozostałe funkcje jak deauth, ignore itp. podobnie zmodyfikowane]

    async function submitPassword() {
        const currentClient = get(client);
        const snifferId = get(activeSnifferId);

        if (!currentClient || !snifferId) {
            addNotification('Client or sniffer not initialized', 'error');
            return;
        }

        try {
            isLoading.set(true);
            const response = await currentClient.accessPointProvidePassword({
                snifferUuid: snifferId,
                bssid: bssid,
                password
            });
            
            if (response.response.state === 0) {
                addNotification('Password accepted', 'success');
                selectedNetwork.set(networkDetails ? 
                    { bssid: networkDetails.bssid, ssid: networkDetails.ssid } : 
                    null
                );
                password = '';
            }
        } catch (e) {
            console.error('Password submission failed:', e);
            addNotification('Failed to submit password', 'error');
        } finally {
            isLoading.set(false);
        }
    }

    $: if (show && bssid) {
        loadNetworkDetails();
    }

    async function ignoreNetwork() {
        const currentClient = get(client);
        const snifferId = get(activeSnifferId);

        if (!currentClient || !snifferId || !networkDetails) {
            addNotification('Missing required configuration', 'error');
            return;
        }

        try {
            isLoading.set(true);
            await currentClient.accessPointIgnore({
                snifferUuid: snifferId,
                bssid: networkDetails.bssid,
                useSsid: false,
                ssid: ''
            });
            
            addNotification('Network added to ignored list', 'success');
            onClose();
        } catch (e) {
            console.error('Failed to ignore network:', e);
            addNotification('Failed to ignore network', 'error');
        } finally {
            isLoading.set(false);
        }
    }

    async function deauthNetwork() {
        const currentClient = get(client);
        const snifferId = get(activeSnifferId);

        if (!currentClient || !snifferId) {
            addNotification('Missing required configuration', 'error');
            return;
        }

        try {
            isLoading.set(true);
            await currentClient.accessPointDeauth({
                snifferUuid: snifferId,
                bssid: bssid
            });
            
            addNotification('Network deauthentication successful', 'success');
        } catch (e) {
            console.error('Failed to deauth network:', e);
            addNotification('Network deauthentication failed', 'error');
        } finally {
            isLoading.set(false);
        }
    }

    async function deauthClient(clientInfo: ClientInfo) {
        const currentClient = get(client);
        const snifferId = get(activeSnifferId);

        if (!currentClient || !snifferId) {
            addNotification('Missing required configuration', 'error');
            return;
        }

        try {
            isLoading.set(true);
            await currentClient.accessPointDeauthClient({
                snifferUuid: snifferId,
                bssid: bssid,
                clientAddr: clientInfo.hwaddr
            });
            
            const displayName = clientInfo.hostname || clientInfo.hwaddr;
            addNotification(`Client ${displayName} deauthentication successful`, 'success');
        } catch (e) {
            console.error('Failed to deauth client:', e);
            addNotification('Client deauthentication failed', 'error');
        } finally {
            isLoading.set(false);
        }
    }
</script>

<div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
    <!-- Notifications -->
    <div class="fixed top-4 right-4 z-50 space-y-2">
        {#each notifications as notification (notification.id)}
            <div
                class="px-4 py-2 rounded shadow-lg text-white transition-all duration-300
                    {notification.type === 'success' ? 'bg-green-500' : 'bg-red-500'}"
                transition:fade
            >
                {notification.message}
            </div>
        {/each}
    </div>

    <!-- Modal Content -->
    <div class="bg-white rounded-lg w-full max-w-3xl max-h-[90vh] overflow-y-auto m-4">
        <div class="sticky top-0 bg-white border-b p-4 flex justify-between items-center">
            <h2 class="text-xl font-semibold">Network Details</h2>
            <button 
                class="text-gray-500 hover:text-gray-700"
                on:click={onClose}
            >
                <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
            </button>
        </div>

        <div class="p-6">
            {#if networkDetails}
                <!-- Network Information -->
                <div class="space-y-6">
                    <div class="grid grid-cols-2 gap-4">
                        <div class="col-span-2 flex gap-2">
                            <Button 
                                variant={isFocused ? "destructive" : "default"}
                                on:click={toggleFocus}
                                disabled={$isLoading}
                            >
                                {isFocused ? 'Stop Focus' : 'Start Focus'}
                            </Button>
                            <Button 
                                variant="outline"
                                on:click={ignoreNetwork}
                                disabled={$isLoading}
                            >
                                Ignore Network
                            </Button>
                            <Button 
                                variant="destructive"
                                on:click={deauthNetwork}
                                disabled={$isLoading}
                            >
                                Deauth Network
                            </Button>
                        </div>

                        <!-- Network Info Grid -->
                        <div>
                            <p class="text-sm text-gray-500">SSID</p>
                            <p class="font-medium">{networkDetails.ssid || 'Hidden Network'}</p>
                        </div>
                        <div>
                            <p class="text-sm text-gray-500">BSSID</p>
                            <p class="font-medium">{networkDetails.bssid}</p>
                        </div>
                        <div>
                            <p class="text-sm text-gray-500">Channel</p>
                            <p class="font-medium">{networkDetails.channel}</p>
                        </div>
                        <div>
                            <p class="text-sm text-gray-500">Security</p>
                            <p class="font-medium">{networkDetails.security.join(', ')}</p>
                        </div>
                        
                        <!-- Password Section -->
                        <div class="col-span-2 pt-4">
                            <div class="space-y-2">
                                <Input
                                    type="password"
                                    placeholder="Network password (optional)"
                                    bind:value={password}
                                />
                                <Button 
                                    variant="default"
                                    on:click={submitPassword}
                                    disabled={!password || $isLoading}
                                    class="w-full"
                                >
                                    Submit Password
                                </Button>
                            </div>
                        </div>
                    </div>

                    <!-- Connected Clients -->
                    <div class="mt-8">
                        <h3 class="text-lg font-medium mb-4">Connected Clients</h3>
                        {#if networkDetails.clients.length === 0}
                            <p class="text-gray-500">No clients connected</p>
                        {:else}
                            <div class="space-y-4">
                                {#each networkDetails.clients as client}
                                    <div class="border rounded-lg p-4">
                                        <div class="grid grid-cols-2 gap-4 mb-4">
                                            <div>
                                                <p class="text-sm text-gray-500">Hostname</p>
                                                <p class="font-medium">{client.hostname || 'Unknown'}</p>
                                            </div>
                                            <div>
                                                <p class="text-sm text-gray-500">MAC Address</p>
                                                <p class="font-mono text-sm">{client.hwaddr}</p>
                                            </div>
                                            {#if client.ipv4}
                                                <div>
                                                    <p class="text-sm text-gray-500">IPv4</p>
                                                    <p class="font-medium">{client.ipv4}</p>
                                                </div>
                                            {/if}
                                            <div>
                                                <p class="text-sm text-gray-500">Signal Strength</p>
                                                <p class="font-medium">{client.rrsi} dBm</p>
                                            </div>
                                        </div>
                                        <Button 
                                            variant="destructive"
                                            on:click={() => deauthClient(client)}
                                            disabled={$isLoading}
                                            size="sm"
                                        >
                                            Deauthenticate Client
                                        </Button>
                                    </div>
                                {/each}
                            </div>
                        {/if}
                    </div>
                </div>
            {:else}
                <div class="flex justify-center items-center h-32">
                    <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900"></div>
                </div>
            {/if}
        </div>
    </div>
</div>