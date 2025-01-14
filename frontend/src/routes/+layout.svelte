<script lang="ts">
	import { onMount } from 'svelte';
	import { client, notifications, connectionStatus, activeSnifferId } from '../lib/stores';
	import { GrpcWebFetchTransport } from '@protobuf-ts/grpcweb-transport';
	import { GRPC_URL } from '$env';
	import { SnifferClient } from '../lib/proto/service.client';
	import { fade, fly } from 'svelte/transition';
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
			notifications.add('Failed to initialize system', 'error');
			connectionStatus.set('disconnected');
		}
	}

	onMount(() => {
		initializeSystem();
	});

	function getNotificationStyles(type: 'success' | 'error') {
		return type === 'success'
			? 'bg-green-100 border-green-400 text-green-700 dark:bg-green-900/50 dark:border-green-700 dark:text-green-200'
			: 'bg-red-100 border-red-400 text-red-700 dark:bg-red-900/50 dark:border-red-700 dark:text-red-200';
	}
</script>

<div class="fixed right-4 top-4 z-50 max-w-sm space-y-2">
	{#each $notifications as notification (notification.id)}
		<div
			transition:fly={{ x: 20, duration: 200 }}
			class="relative rounded-lg border px-4 py-3 shadow-lg {getNotificationStyles(
				notification.type
			)}"
		>
			{notification.message}
			<button
				class="absolute right-0 top-0 p-2"
				on:click={() => notifications.remove(notification.id)}
			>
				<svg class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
					<path
						fill-rule="evenodd"
						d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z"
						clip-rule="evenodd"
					/>
				</svg>
			</button>
		</div>
	{/each}
</div>

<div class="bg-background text-foreground min-h-screen">
	<header class="bg-background border-border border-b">
		<div class="mx-auto flex max-w-7xl items-center space-x-3 px-4 py-4">
			<img src="/logo.png" alt="Yarilo Logo" class="h-14 w-14" />
			<h1 class="text-xl font-semibold text-gray-900 dark:text-white">Yarilo</h1>

			<!-- Przycisk do przełączania trybu -->
			<button
				class="ml-auto rounded-lg p-2 hover:bg-gray-100 dark:hover:bg-[#363640]"
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

	<main class="mx-auto max-w-7xl px-4 py-6">
		{#if !clientInitialized}
			<div class="flex h-32 items-center justify-center">
				<div
					class="h-8 w-8 animate-spin rounded-full border-b-2 border-gray-900 dark:border-white"
				/>
			</div>
		{:else}
			<slot />
		{/if}
	</main>
</div>
