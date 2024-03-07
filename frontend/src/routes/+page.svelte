<script lang="ts">
	import Error from '$components/error.svelte';
	import APList from '$components/aplist.svelte';

	import { client } from '$lib/stores';
	import type { RpcError } from '@protobuf-ts/runtime-rpc';

	let errMsg: string = ''; // they are reactive! changing them triggers a rerender
	let networkList: string[] = [];
	let focusCandidate: string | undefined;
	let focusedNetwork: string = '';

	const displayError = (error: RpcError) => {
		console.error('Error!', error);
		errMsg = error.code;
		setTimeout(() => {
			errMsg = '';
		}, 3000);
	};

	const focusNetwork = (ap: string) => {
		$client
			.focusNetwork({ ssid: ap })
			.then(() => {
				console.log('Network focused!', ap);
				focusedNetwork = ap;
			})
			.catch(displayError);
	};

	const unfocusNetwork = () => {
		$client
			.stopFocus({})
			.then(() => {
				console.log('Network unfocused!');
				focusedNetwork = '';
			})
			.catch(displayError);
	};

	$: {
		if (focusCandidate !== undefined) {
			if (focusCandidate.length !== 0) {
				focusNetwork(focusCandidate);
			} else {
				unfocusNetwork();
			}
		}
	}
</script>

<APList bind:errMsg bind:focusedNetwork={focusCandidate} {networkList} />

<p>Focused network (after gprc call): "{focusedNetwork}"</p>

{#if errMsg.length !== 0}
	<Error message={errMsg} />
{/if}
