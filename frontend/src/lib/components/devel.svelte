<script lang="ts">
	export let errMsg: string | null;
	export let networkList: string[] = [];
	export let focusedNetwork: string | null;

	const mynet = 'Schronisko Bielsko Biala';
	const myclient = 'de:4e:d5:b2:3d:2e';
	const myfilename = 'test.pcap';
	const mynetname = 'wlp5s0f3u2';

	let password: string = '';

	import type { RpcError, FinishedUnaryCall } from '@protobuf-ts/runtime-rpc';
	import {
		type Empty,
		type NetworkList,
		type NetworkInfo,
		type NetworkName,
		type DecryptRequest,
		type RecordingsList,
		type Packet,
		DataLinkType
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
				.getAccessPoint({ snifferId: 0n, ssid: ap })
				.then((data: FinishedUnaryCall<NetworkName, NetworkInfo>) => {
					console.log(data.response);
				})
				.catch(displayError);
		});
	};

	const providePassword = (ap: string) => () => {
		ensureConnected().then(() => {
			$client
				.providePassword({ snifferId: 0n, ssid: ap, passwd: password })
				.then((data: FinishedUnaryCall<DecryptRequest, Empty>) => {
					console.log(data);
				})
				.catch(displayError);
		});
	};

	const deauth = (ap: string, client: string) => () => {
		ensureConnected().then(() => {
			$client
				.deauthNetwork({ snifferId: 0n, network: { snifferId: 0n, ssid: ap }, userAddr: client })
				.then(() => {
					console.log('Success');
				})
				.catch(displayError);
		});
	};

	const ignoreNetwork = (ap: string) => () => {
		ensureConnected().then(() => {
			$client
				.ignoreNetwork({ snifferId: 0n, ssid: ap })
				.then(() => {
					console.log('Ignored', ap);
				})
				.catch(displayError);
		});
	};

	const getIgnoredNetworks = () => {
		ensureConnected().then(() => {
			$client
				.getIgnoredNetworks({ id: 0n })
				.then((data: FinishedUnaryCall<Empty, NetworkList>) => {
					console.log(data);
				})
				.catch(displayError);
		});
	};

	const createRecording = (ap: string, decrypted: boolean) => () => {
		ensureConnected().then(() => {
			$client
				.recordingCreate({
					snifferId: 0n,
					singularAp: ap !== '',
					ssid: ap,
					dataLink: decrypted ? DataLinkType.ETH2 : DataLinkType.DOT11
				})
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
			const call = $client.getDecryptedPackets({ snifferId: 0n, ssid: ap });
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
			const call = $client.loadRecording({ snifferId: 0n, name: filename });
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

	// Create a sniffer instance
	const fileSnifferCreate = (filename: string) => () => {
		ensureConnected().then(() => {
			$client
				.snifferCreate({
					isFileBased: true,
					netIfaceName: '',
					filename: filename
				})
				.then((data) => {
					console.log('Sniffer created with ID', data.response);
				})
				.catch(displayError);
		});
	};

	const netSnifferCreate = (netname: string) => () => {
		ensureConnected().then(() => {
			$client
				.snifferCreate({
					isFileBased: false,
					netIfaceName: netname,
					filename: ''
				})
				.then((data) => {
					console.log('Sniffer created with ID', data.response);
				})
				.catch(displayError);
		});
	};

	// Destroy a sniffer instance
	const snifferDestroy = () => {
		ensureConnected().then(() => {
			$client
				.snifferDestroy({ id: 0n })
				.then((data) => {
					console.log('Sniffer destroyed', data.response);
				})
				.catch(displayError);
		});
	};

	// List active sniffers
	const snifferList = () => {
		ensureConnected().then(() => {
			$client
				.snifferList({})
				.then((data) => {
					console.log('Active sniffers', data.response);
				})
				.catch(displayError);
		});
	};

	// List sniffer files (pcap recordings of 802.11 networks)
	const sniffFileList = () => {
		ensureConnected().then(() => {
			$client
				.sniffFileList({})
				.then((data) => {
					console.log('Sniffer files', data.response);
				})
				.catch(displayError);
		});
	};

	// List interfaces that can be used for sniffing
	const sniffInterfaceList = () => {
		ensureConnected().then(() => {
			$client
				.sniffInterfaceList({})
				.then((data) => {
					console.log('Sniffer interfaces', data.response);
				})
				.catch(displayError);
		});
	};
</script>

<Input type="password" bind:value={password} placeholder="Password!" />
<div>
	<h1>General</h1>
	<Button on:click={providePassword(mynet)}>Confirm the password</Button>
	<Button on:click={getAccessPointDetails(mynet)}>Get the details of the network</Button>
	<Button on:click={deauth(mynet, myclient)}>Get the details of the network</Button>
	<Button on:click={ignoreNetwork(mynet)}>Ignore the network</Button>
	<Button on:click={getIgnoredNetworks}>Get the ignored networks</Button>
</div>

<div>
	<h1>Recordings</h1>
	<Button on:click={createRecording(mynet, true)}>Save Decrypted Traffic For One network</Button>
	<Button on:click={createRecording(mynet, false)}>Save All Traffic For One Network</Button>
	<Button on:click={createRecording('', true)}>Save Decrypted Traffic</Button>
	<Button on:click={createRecording('', false)}>Save All Traffic</Button>
	<Button on:click={loadRecording('Coherer-10-03-2024-23:09.pcap')}>Load recording</Button>
	<Button on:click={getAvailableRecordings}>Get available recordings</Button>
</div>

<div>
	<h1>Sniffers</h1>
	<Button on:click={fileSnifferCreate(myfilename)}>Create file Sniffer</Button>
	<Button on:click={netSnifferCreate(mynetname)}>Create network Sniffer</Button>
	<Button on:click={snifferDestroy}>Destroy Sniffer</Button>
	<Button on:click={snifferList}>List Active Sniffers</Button>
	<Button on:click={sniffFileList}>List Sniffer Files</Button>
	<Button on:click={sniffInterfaceList}>List Sniffer Interfaces</Button>
</div>

<div>
	<h1>Other</h1>
	<Button on:click={getDecryptedPackets(mynet)}>Get Decrypted Traffic</Button>
</div>
