<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import { ExclamationTriangle } from 'radix-icons-svelte';
	import * as Alert from '$lib/components/ui/alert';
	import type { SniffinsonClient } from '$lib/proto/PacketsServiceClientPb';
	import { api } from '$lib/proto/conn';
	import { Empty } from '$lib/proto/packets_pb';

	let conn: SniffinsonClient;
	$: conn = $api!; // Get the client from the store

	function fetchAvailableNetworks() {
		console.log('Hello from the button');
		console.log(conn);
		conn.getIgnoredNetworks(new Empty(), null, (err, resp) => {
		      console.log('GOT response', err, resp);
		});
	}
</script>

<h1>This will be the homepage i guess</h1>

+<Button on:click={fetchAvailableNetworks}>Get available networks</Button>

<Alert.Root variant="destructive" class="absolute bottom-0 right-0 m-4 w-1/3">
	<ExclamationTriangle class="h-4 w-4" />
	<Alert.Title>This is an error!</Alert.Title>
	<Alert.Description
		>There has been an error with the API, what do we do now? Why isn't this popup dark?</Alert.Description
	>
</Alert.Root>
