<script lang="ts">
	export let errMsg: string | null;
	export let networkList: string[] = [];
	export let focusedNetwork: string | null;

	const mynet = 'Coherer';
	const myclient = 'de:4e:d5:b2:3d:2e';

	let password: string = '';

	import type { RpcError, FinishedUnaryCall } from '@protobuf-ts/runtime-rpc';
	import type {
		Empty,
		NetworkList,
		NetworkInfo,
		NetworkName,
		DecryptRequest,
		RecordingsList,
		Packet
	} from '$lib/proto/packets';
	import { ensureConnected, client } from '$stores';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';

	const displayError = (error: RpcError) => {
		console.error('Error!', error);
		errMsg = error.code;
		setTimeout(() => {
			errMsg = null;
		}, 3000);
	};

	const getAccessPointDetails = (ap: string) => () => {
		ensureConnected().then(() => {
			$client
				.getAccessPoint({ ssid: ap })
				.then((data: FinishedUnaryCall<NetworkName, NetworkInfo>) => {
					console.log(data.response);
				})
				.catch(displayError);
		});
	};

	const providePassword = (ap: string) => () => {
		ensureConnected().then(() => {
			$client
				.providePassword({ ssid: ap, passwd: password })
				.then((data: FinishedUnaryCall<DecryptRequest, Empty>) => {
					console.log(data);
				})
				.catch(displayError);
		});
	};

	const deauth = (ap: string, client: string) => () => {
		ensureConnected().then(() => {
			$client
				.deauthNetwork({ network: { ssid: ap }, userAddr: client })
				.then(() => {
					console.log('Success');
				})
				.catch(displayError);
		});
	};

	const ignoreNetwork = (ap: string) => () => {
		ensureConnected().then(() => {
			$client
				.ignoreNetwork({ ssid: ap })
				.then(() => {
					console.log('Ignored', ap);
				})
				.catch(displayError);
		});
	};

	const getIgnoredNetworks = () => {
		ensureConnected().then(() => {
			$client
				.getIgnoredNetworks({})
				.then((data: FinishedUnaryCall<Empty, NetworkList>) => {
					console.log(data);
				})
				.catch(displayError);
		});
	};

	const saveDecryptedTraffic = (ap: string) => () => {
		ensureConnected().then(() => {
			$client
				.saveDecryptedTraffic({ ssid: ap })
				.then(() => {
					console.log('Saved traffic for', ap);
				})
				.catch(displayError);
		});
	};

	const getAvailableRecordings = () => {
		ensureConnected().then(() => {
			$client
				.getAvailableRecordings({})
				.then((data: FinishedUnaryCall<Empty, RecordingsList>) => {
					console.log('Saved traffic for', data.response);
				})
				.catch(displayError);
		});
	};

	const getDecryptedPackets = (ap: string) => () => {
		ensureConnected().then(async () => {
			const call = $client.getDecryptedPackets({ ssid: ap });
			call.responses.onMessage((message: Packet) => {
				console.log(
					`Packet: ${message.protocol} from ${message.from?.iPv4Address}:${message.from?.port} (${message.from?.mACAddress} to ${message.to?.iPv4Address}:${message.to?.port} (${message.to?.mACAddress}`
				);
			});

			call.responses.onError((reason: Error) => {
				console.log(`Get derypted packets error: ${reason}`);
			});

			call.responses.onComplete(() => {
				console.log('Get derypted packets finished');
			});
		});
	};

	const loadRecording = (filename: string) => () => {
		ensureConnected().then(async () => {
			const call = $client.loadRecording({ name: filename });
			call.responses.onMessage((message: Packet) => {
				console.log(
					`Packet: ${message.protocol} from ${message.from?.iPv4Address}:${message.from?.port} (${message.from?.mACAddress} to ${message.to?.iPv4Address}:${message.to?.port} (${message.to?.mACAddress}`
				);
			});

			call.responses.onError((reason: Error) => {
				console.log(`Load recording error: ${reason}`);
			});

			call.responses.onComplete(() => {
				console.log('Load recording finished');
			});
		});
	};
</script>

<Input type="password" bind:value={password} placeholder="Password!" />
<Button on:click={providePassword(mynet)}>Confirm the password</Button>
<Button on:click={getAccessPointDetails(mynet)}>Get the details of the network</Button>
<Button on:click={deauth(mynet, myclient)}>Get the details of the network</Button>
<Button on:click={ignoreNetwork(mynet)}>Ignore the network</Button>
<Button on:click={getIgnoredNetworks}>Get the ignored networks</Button>
<Button on:click={saveDecryptedTraffic(mynet)}>Save Decrypted Traffic</Button>
<Button on:click={getDecryptedPackets(mynet)}>Get Decrypted Traffic</Button>
<Button on:click={loadRecording('Coherer-10-03-2024-23:09.pcap')}>Load recording</Button>
<Button on:click={getAvailableRecordings}>Get available recordings</Button>
