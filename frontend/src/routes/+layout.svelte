<script lang="ts">
	import '../app.pcss';

	import { onMount } from 'svelte';
	import { SniffinsonClient } from '$proto/packets.client';

	import { grpcClient } from '$stores';
	import { GRPC_URL } from '$env';
	import { GrpcWebFetchTransport } from '@protobuf-ts/grpcweb-transport';

	onMount(() => {
		console.log(GRPC_URL);
		const greeterService = new SniffinsonClient(
			new GrpcWebFetchTransport({
				baseUrl: GRPC_URL
			})
		);

		grpcClient.set(greeterService);
	});
</script>

<main>
	<slot />
</main>
