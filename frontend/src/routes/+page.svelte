<script lang="ts">
    import { 
        error,
        isLoading,
        connectionStatus,
        activeSnifferId
    } from '../lib/stores';
    import PacketViewer from '../lib/components/PacketViewer.svelte';
    import NetworkList from '../lib/components/NetworkList.svelte';
    import SnifferPanel from '../lib/components/SnifferPanel.svelte';
    import IgnoredNetworksPanel from '../lib/components/IgnoredNetworksPanel.svelte';

    // Status połączenia
    $: connectionText = {
        'disconnected': 'Disconnected',
        'connecting': 'Connecting...',
        'connected': 'Connected'
    }[$connectionStatus];

    // Status sniffera
    $: snifferStatus = $activeSnifferId ? 'Initialized' : 'Not Initialized';
</script>

<div class="grid grid-cols-12 gap-4 p-4">
    <div class="col-span-3 space-y-4">
        <!-- Status info - pokazuj tylko gdy jest błąd lub aktywne ładowanie -->
        {#if $error || $isLoading}
            <div class="p-4 bg-white rounded-lg shadow">
                <div class="text-sm">
                    <p>Connection: <span class={$connectionStatus === 'connected' ? 'text-green-600' : 'text-red-600'}>
                        {connectionText}
                    </span></p>
                    <p>Sniffer: <span class={$activeSnifferId ? 'text-green-600' : 'text-red-600'}>
                        {snifferStatus}
                    </span></p>
                </div>
            </div>
        {/if}

        <!-- Sniffer Management Panel -->
        <SnifferPanel />

        <!-- Networks List -->
        <NetworkList />

        <!-- Ignored Networks Panel -->
        <IgnoredNetworksPanel />
    </div>
    
    <!-- Packet Viewer -->
    <div class="col-span-9">
        <PacketViewer />
    </div>
</div>