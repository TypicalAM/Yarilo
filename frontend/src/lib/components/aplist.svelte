<script lang="ts">
	export let errMsg: string | null;
	export let focusedNetwork: string | null;
	export let networkList: string[] = [];

	import Reload from 'svelte-radix/Reload.svelte';

	import { client, ensureConnected } from '$stores';
	import { Separator } from '$lib/components/ui/separator';
	import { Switch } from '$lib/components/ui/switch';
	import { Label } from '$lib/components/ui/label';
	import { Button } from '$lib/components/ui/button';

	import type { RpcError, FinishedUnaryCall } from '@protobuf-ts/runtime-rpc';
	import type { Empty, NetworkList, FocusState } from '$lib/proto/packets';
	import { onMount } from 'svelte';

	const displayError = (error: RpcError) => {
		console.error('Error!', error);
		errMsg = error.code;
		setTimeout(() => {
			errMsg = null;
		}, 3000);
	};

	const refreshAccessPoints = () => {
		ensureConnected().then(() => {
			$client
				.getAllAccessPoints({})
				.then((data: FinishedUnaryCall<Empty, NetworkList>) => {
					console.log('New network list fetched!', networkList);
					networkList = data.response.names;
				})
				.catch(displayError);
		});
	};

	const focusNetwork = (ap: string) => {
		ensureConnected().then(() => {
			$client
				.focusNetwork({ ssid: ap })
				.then(() => {
					console.log('Network focused!', ap);
					focusedNetwork = ap;
				})
				.catch(displayError);
		});
	};

	const unfocusNetwork = () => {
		ensureConnected().then(() => {
			$client
				.stopFocus({})
				.then(() => {
					console.log('Network unfocused!');
					focusedNetwork = null;
				})
				.catch(displayError);
		});
	};

	const getFocusedNetwork = () => {
		// If we are mounting client-side, then run this
		ensureConnected().then(() => {
			$client
				.getFocusState({})
				.then((data: FinishedUnaryCall<Empty, FocusState>) => {
					console.log('Got network focus from the server');
					if (data.response.focused && data.response.name) {
						focusedNetwork = data.response.name.ssid;
					}
				})
				.catch(displayError);
		});
	};

	const changeChecked = (ap: string) => (checked: boolean) =>
		checked ? focusNetwork(ap) : unfocusNetwork();

	onMount(() => {
		getFocusedNetwork();
		refreshAccessPoints();
	});
</script>

<div class="w-1/6 flex flex-col rounded-xl border bg-primary p-4 text-primary-foreground">
	<div class="mb-6 mt-1 flex h-4 items-center justify-between">
		{#if focusedNetwork}
			<h4 class="text-md px-2 font-medium leading-none">Focused: {focusedNetwork}</h4>
		{:else}
			<h4 class="text-md px-2 font-medium leading-none">Focused: Not Really</h4>
		{/if}
		<Button on:click={refreshAccessPoints} class="mt-1 hover:bg-secondary/30" size="icon">
			<Reload class="w-4 animate-spin" />
		</Button>
	</div>

	{#each networkList as ap}
		<div class="w-64 mx-2 flex items-center justify-between">
			<Label for={ap}>{ap}</Label>
			<Switch id={ap} onCheckedChange={changeChecked(ap)} />
		</div>
		<Separator class="w-64 my-2" />
	{/each}
</div>
