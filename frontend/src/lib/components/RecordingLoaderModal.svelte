<script lang="ts">
    import { Button } from "./ui/button";
    import type { Recording } from '../proto/service';
    import type { RpcError, ServerStreamingCall } from '@protobuf-ts/runtime-rpc';
    import type { Packet, RecordingLoadDecryptedRequest } from '../proto/service';
    import { client, error, isLoading, packets } from '../stores';
    import { get } from 'svelte/store';

    export let show = false;
    export let onClose = () => {};

    let recordings: Recording[] = [];

    async function loadRecordings() {
        try {
            const currentClient = get(client);
            if (!currentClient) {
                throw new Error('Client not initialized');
            }

            isLoading.set(true);
            
            console.log('Requesting recordings list...');
            
            const response = await currentClient.recordingList({
                allowedTypes: [3] 
            });
            
            // Dodajmy szczegółowe logowanie odpowiedzi
            console.log('Raw response:', response);
            console.log('Response recordings:', JSON.stringify(response.response.recordings, null, 2));
            
            recordings = response.response.recordings;

            // Sprawdźmy co faktycznie jest w recordings po przypisaniu
            console.log('Parsed recordings array:', JSON.stringify(recordings, null, 2));

            if (recordings.length === 0) {
                error.set('No recordings available');
            }
        } catch (e) {
            console.error('Failed to load recordings:', e);
            error.set(e instanceof Error ? e.message : 'Failed to load recordings list');
        } finally {
            isLoading.set(false);
        }
    }

    async function loadRecording(recording: Recording) {
        try {
            const currentClient = get(client);
            if (!currentClient) {
                throw new Error('Client not initialized');
            }

            isLoading.set(true);
            
            console.log('Attempting to load recording:', {
                uuid: recording.uuid,
                filename: recording.filename,
                displayName: recording.displayName
            });
            
            packets.set([]);
            
            const request = {
                uuid: recording.uuid,
                includePayload: true
            };
            
            console.log('Sending load request:', request);
            
            const call: ServerStreamingCall<RecordingLoadDecryptedRequest, Packet> = 
                currentClient.recordingLoadDecrypted(request);
            
            console.log('Stream obtained, starting to read packets...');

            let packetCount = 0;

            try {
                for await (const packet of call.responses) {
                    if (!packet) {
                        console.warn('Received null/undefined packet');
                        continue;
                    }
                    
                    packets.update(current => {
                        const updated = [...current, packet];
                        if (updated.length > 1000) {
                            return updated.slice(-1000);
                        }
                        return updated;
                    });
                    packetCount++;

                    if (packetCount % 100 === 0) {
                        console.log(`Loaded ${packetCount} packets...`);
                    }
                }
            } catch (streamError) {
                console.error('Error during stream processing:', streamError);
                throw streamError;
            }

            console.log(`Successfully loaded ${packetCount} packets`);
            error.set(`Loaded ${packetCount} packets successfully`);
            onClose();
        } catch (e) {
            console.error('Failed to load recording:', e);
            
            const rpcError = e as RpcError;
            error.set(`Failed to load recording: ${rpcError.message || 'Unknown error'}`);
            
            // Logujemy tylko kod błędu, który na pewno istnieje w RpcError
            if (rpcError.code) console.error('Error code:', rpcError.code);
        } finally {
            isLoading.set(false);
        }
    }

    $: if (show) {
        loadRecordings();
    }

    function getDataLinkTypeLabel(type: number): string {
        switch (type) {
            case 0: return 'RADIOTAP';
            case 1: return 'RAW80211';
            case 2: return 'ETH2';
            default: return 'Unknown';
        }
    }

    function getDisplayName(recording: Recording): string {
        const name = recording.displayName || recording.filename;
        if (!name) return `Recording ${recording.uuid.slice(0, 8)}`;
        
        // Rozdzielamy nazwę na części: NAZWA_UUID_DATA.pcapng
        const parts = name.split('_');
        if (parts.length >= 2) {
            return parts[0]; // Zwracamy tylko pierwszą część (nazwa nadana przez użytkownika)
        }
        
        return name;
    }
</script>

<div class="fixed inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center z-50"
     class:hidden={!show}>
    <div class="bg-card text-card-foreground rounded-lg w-full max-w-2xl max-h-[80vh] flex flex-col">
        <div class="flex justify-between items-center p-6 border-border">
            <h2 class="text-xl font-semibold text-foreground">Load Recording</h2>
            <button 
                class="text-muted-foreground hover:text-foreground"
                on:click={onClose}
            >
                <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
            </button>
        </div>

        <div class="flex-1 overflow-y-auto p-6">
            {#if $isLoading}
                <div class="flex justify-center items-center h-32">
                    <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
                </div>
            {:else if recordings.length === 0}
                <p class="text-center text-muted-foreground py-8">No recordings available</p>
            {:else}
                <div class="space-y-2">
                    {#each recordings as recording}
                        <div class="border-border rounded-lg p-4 hover:bg-muted/50">
                            <div class="flex justify-between items-center">
                                <div>
                                    <p class="font-medium text-foreground">{getDisplayName(recording)}</p>
                                    <p class="text-sm text-muted-foreground">Type: {getDataLinkTypeLabel(recording.datalink)}</p>
                                    <p class="text-xs text-muted-foreground font-mono">{recording.uuid}</p>
                                </div>
                                <Button
                                    variant="outline"
                                    size="sm"
                                    on:click={() => loadRecording(recording)}
                                    disabled={$isLoading}
                                >
                                    Load
                                </Button>
                            </div>
                        </div>
                    {/each}
                </div>
            {/if}
        </div>
    </div>
</div>