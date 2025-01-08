<script lang="ts">
    import { onMount } from 'svelte';
    import { client, error, connectionStatus, activeSnifferId } from '../lib/stores';
    import { GrpcWebFetchTransport } from '@protobuf-ts/grpcweb-transport';
    import { GRPC_URL } from '$env';
    import { SnifferClient } from '../lib/proto/service.client';
    import '../app.pcss';

    let clientInitialized = false;

    async function initializeSystem() {
        try {
            // 1. Inicjalizacja klienta gRPC
            console.log('Initializing gRPC client with URL:', GRPC_URL);
            connectionStatus.set('connecting');
            
            const transport = new GrpcWebFetchTransport({
                baseUrl: GRPC_URL
            });
            
            const snifferClient = new SnifferClient(transport);
            client.set(snifferClient);
            connectionStatus.set('connected');
            
            // 2. Sprawdzenie istniejących snifferów
            const snifferResponse = await snifferClient.snifferList({});
            const existingSniffers = snifferResponse.response.sniffers;

            if (existingSniffers.length > 0) {
                // Jeśli jest aktywny sniffer, ustaw jego ID
                activeSnifferId.set(existingSniffers[0].uuid);
            }

            clientInitialized = true;
            console.log('System initialized successfully');
        } catch (e) {
            console.error('Failed to initialize system:', e);
            error.set('Failed to initialize system');
            connectionStatus.set('disconnected');
        }
    }

    onMount(() => {
        initializeSystem();
    });
</script>

<div class="min-h-screen bg-background text-foreground">
    <header class="bg-background border-b border-border">
        <div class="max-w-7xl mx-auto px-4 py-4 flex items-center space-x-3">
            <img src="/logo.png" alt="Yarilo Logo" class="h-14 w-14" />
            <h1 class="text-xl font-semibold text-gray-900 dark:text-white">Yarilo</h1>
            
            <!-- Przycisk do przełączania trybu -->
            <button 
                class="ml-auto p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-[#363640]"
                on:click={() => document.documentElement.classList.toggle('dark')}
            >
                <!-- Ikona słońca/księżyca -->
                <svg 
                    xmlns="http://www.w3.org/2000/svg" 
                    class="h-5 w-5 text-gray-500 dark:text-gray-400"
                    fill="none" 
                    viewBox="0 0 24 24" 
                    stroke="currentColor"
                >
                    <path 
                        class="dark:hidden"
                        stroke-linecap="round" 
                        stroke-linejoin="round" 
                        stroke-width="2" 
                        d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" 
                    />
                    <path 
                        class="hidden dark:block"
                        stroke-linecap="round" 
                        stroke-linejoin="round" 
                        stroke-width="2" 
                        d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707" 
                    />
                </svg>
            </button>
        </div>
    </header>

    <main class="max-w-7xl mx-auto px-4 py-6">
        {#if !clientInitialized}
            <div class="flex justify-center items-center h-32">
                <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900 dark:border-white"></div>
            </div>
        {:else}
            {#if $error}
            <div class="mb-4 bg-red-100 dark:bg-red-900/50 border border-red-400 dark:border-red-700 text-red-700 dark:text-red-200 px-4 py-3 rounded relative">
                {$error}
                    <button 
                        class="absolute top-0 bottom-0 right-0 px-4"
                        on:click={() => error.set(null)}
                    >
                        <span class="sr-only">Dismiss</span>
                        <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
                        </svg>
                    </button>
                </div>
            {/if}
            <slot></slot>
        {/if}
    </main>
</div>
