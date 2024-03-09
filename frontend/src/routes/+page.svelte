<script lang="ts">
	import Error from '$components/error.svelte';
	import APList from '$components/aplist.svelte';

	import { ensureConnected } from '$stores';
	import { onMount } from 'svelte';

	import type { RpcError } from '@protobuf-ts/runtime-rpc';

	let errMsg: string | null;
	let networkList: string[] = [];
	let focusedNetwork: string | null;
	let connecting = true;

	const displayError = (error: RpcError) => {
		console.error('Error!', error);
		errMsg = error.code;
		setTimeout(() => {
			errMsg = null;
		}, 3000);
	};

	onMount(() => {
		ensureConnected().then(() => {
			connecting = false;
		});
	});
</script>

<APList bind:errMsg bind:focusedNetwork {networkList} />

{#if errMsg}
	<Error message={errMsg} />
{/if}

{#if connecting}
	<p>Connecting</p>
{:else}
	<p>Connected</p>
{/if}
