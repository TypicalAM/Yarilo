<script lang="ts">
    import { Button } from "./ui/button";
    import { Input } from "./ui/input";
    import type { BasicNetworkInfo } from '../proto/service';
    
    export let show = false;
    export let onClose = () => {};
    export let onSave = (name: string) => {};
    export let network: BasicNetworkInfo | null = null;

    let recordingName = '';

    $: if (show && network && !recordingName) {
    // Format: nazwa_UUID_DATA.pcapng
    const date = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    const time = new Date().toTimeString().slice(0, 5).replace(':', '');
    recordingName = `${network.ssid}_${date}_${time}`;  // usuńmy UUID z nazwy, backend sam go doda
}

    function handleSave() {
        if (recordingName.trim()) {
            onSave(recordingName.trim());
            recordingName = ''; 
        }
    }
</script>

<div class="fixed inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center z-50" 
     class:hidden={!show}>
    <div class="bg-card text-card-foreground rounded-lg w-full max-w-md p-6">
        <div class="flex justify-between items-center mb-6">
            <h2 class="text-xl font-semibold text-foreground">Save Network Traffic</h2>
            <button 
                class="text-muted-foreground hover:text-foreground"
                on:click={onClose}
            >
                <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
            </button>
        </div>

        <div class="space-y-4">
            <div>
                <label for="recording-name" class="block text-sm font-medium text-foreground mb-1">
                    Recording Name
                </label>
                <Input
                    id="recording-name"
                    type="text"
                    bind:value={recordingName}
                    placeholder="Enter recording name"
                    class="bg-background"
                />
                {#if network}
                <p class="text-sm text-muted-foreground mt-1">
                    Will save traffic from network: {network.ssid}
                </p>
                {:else}
                <p class="text-sm text-muted-foreground mt-1">
                    Will save all traffic from current sniffer
                </p>
                {/if}
            </div>

            <div class="flex justify-end space-x-2">
                <Button
                    variant="outline"
                    on:click={onClose}
                >
                    Cancel
                </Button>
                <Button
                    variant="default"
                    on:click={handleSave}
                    disabled={!recordingName.trim()}
                >
                    Save Traffic
                </Button>
            </div>
        </div>
    </div>
</div>