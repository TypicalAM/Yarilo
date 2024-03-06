<script lang="ts">
	import { client } from '$stores';

	import { Button } from '$lib/components/ui/button';
	import { ExclamationTriangle } from 'radix-icons-svelte';
	import * as Alert from '$lib/components/ui/alert';

	const fetchAvailableNetworks = async () => {
		console.log('Hello from the button');
		let { response } = await $client.getAllAccessPoints({});
		console.log(response);
	};
</script>

<h1>This will be the homepage i guess</h1>

<Button on:click={fetchAvailableNetworks}>Get available networks</Button>

<Alert.Root variant="destructive" class="absolute bottom-0 right-0 m-4 w-1/3">
	<ExclamationTriangle class="h-4 w-4" />
	<Alert.Title>This is an error!</Alert.Title>
	<Alert.Description
		>There has been an error with the API, what do we do now? Why isn't this popup dark?</Alert.Description
	>
</Alert.Root>
