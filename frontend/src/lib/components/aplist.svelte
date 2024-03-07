<script lang="ts">
	export let errMsg: string = '';
	export let focusedNetwork: string | undefined;
	export let networkList: string[] = [];

	import Reload from 'svelte-radix/Reload.svelte';

	import { client } from '$stores';
	import { Separator } from '$lib/components/ui/separator';
	import { Switch } from '$lib/components/ui/switch';
	import { Label } from '$lib/components/ui/label';
	import { Button } from '$lib/components/ui/button';

	import type { RpcError, FinishedUnaryCall } from '@protobuf-ts/runtime-rpc';
	import type { Empty, NetworkList } from '$lib/proto/packets';

	const displayError = (error: RpcError) => {
		console.error('Error!', error);
		errMsg = error.code;
		setTimeout(() => {
			errMsg = '';
		}, 3000);
	};

	const refreshAccessPoints = () => {
		$client
			.getAllAccessPoints({})
			.then((data: FinishedUnaryCall<Empty, NetworkList>) => {
				console.log('New network list fetched!', networkList);
				networkList = data.response.names;
			})
			.catch(displayError);
	};
</script>

<div class="h-72 w-64 rounded-xl border bg-primary p-4 text-primary-foreground">
	<div class="mb-6 mt-1 flex h-4 items-center justify-between">
		<h4 class="text-md px-2 font-medium leading-none">Available networks</h4>
		<Button on:click={refreshAccessPoints} class="mt-1 hover:bg-secondary/30" size="icon">
			<Reload class="w-4 animate-spin" />
		</Button>
	</div>

	{#each networkList as ap}
		<div class="mx-2 flex items-center justify-between">
			<Label for={ap}>{ap}</Label>
			<Switch
				id={ap}
				onCheckedChange={(newState) => {
					console.log('New focus change:', newState, ap);
					focusedNetwork = newState ? ap : '';
				}}
			/>
		</div>
		<Separator class="my-2" />
	{/each}
</div>
