<script lang="ts">
	import '../app.pcss';

	import { onMount } from 'svelte';
	import { SnifferClient } from '$proto/packets.client';

	import { client } from '$stores';
	import { GRPC_URL } from '$env';
	import { GrpcWebFetchTransport } from '@protobuf-ts/grpcweb-transport';

	onMount(() => {
		console.log('Creating client');
		const greeterService = new SnifferClient(
			new GrpcWebFetchTransport({
				baseUrl: GRPC_URL
			})
		);

		console.log('Client created');
		client.set(greeterService);
	});
</script>

<main>
	<slot />
</main>
