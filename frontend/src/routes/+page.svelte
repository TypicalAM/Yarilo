<script lang="ts">
	import Error from '$components/error.svelte';
	import APList from '$components/aplist.svelte';
	import { ensureConnected, client } from '$stores';
	import { onMount } from 'svelte';
	import type { RpcError } from '@protobuf-ts/runtime-rpc';
	import type { NetworkList, NetworkInfo, FocusState, NetworkName } from '$proto/packets';
	import type { SnifferClient } from '$proto/packets.client';
	import type { Packet } from '$proto/packets';

	let errMsg: string | null;
	let networkList: NetworkList | null = null;
	let focusedNetwork: NetworkInfo | null = null;
	let focusState: FocusState | null = null;
	let connecting = true;
	let password = "";
	let showNetworkList = false;
	let snifferClient: SnifferClient;
	let packets: Packet[] = [];
	let selectedNetworks: Set<string> = new Set();

	const displayError = (error: RpcError) => {
		console.error('Error!', error);
		errMsg = error.code;
		setTimeout(() => {
			errMsg = null;
		}, 3000);
	};

	onMount(async () => {
		try {
			await ensureConnected();
			client.subscribe(value => {
				if (value) {
					snifferClient = value;
					connecting = false;
					getAllAccessPoints();
					getFocusState();
				}
			});
		} catch (error) {
			displayError(error as RpcError);
			connecting = false;
		}
	});

	async function getAllAccessPoints() {
        try {
            const response = await snifferClient.getAllAccessPoints({});
            networkList = response.response;
            showNetworkList = true;
            selectedNetworks.clear();
        } catch (error) {
            displayError(error as RpcError);
        }
    }

	function toggleNetworkSelection(network: string) {
        if (selectedNetworks.has(network)) {
            selectedNetworks.delete(network);
        } else {
            selectedNetworks.add(network);
        }
        selectedNetworks = selectedNetworks;
    }

	async function getPackets() {
        if (focusedNetwork) {
            try {
                const call = snifferClient.getDecryptedPackets({ ssid: focusedNetwork.name });
                packets = [];
                for await (const packet of call.responses) {
                    packets = [...packets, packet];
                    if (packets.length > 10) packets.shift(); // Keep only the last 10 packets
                }
            } catch (error) {
                displayError(error as RpcError);
            }
        }
    }

	async function getAccessPoint(networkName: string) {
        try {
            const response = await snifferClient.getAccessPoint({ ssid: networkName });
            focusedNetwork = response.response;
            getPackets(); // Start fetching packets for this network
        } catch (error) {
            displayError(error as RpcError);
        }
    }

	async function getFocusState() {
		try {
			const response = await snifferClient.getFocusState({});
			focusState = response.response;
		} catch (error) {
			displayError(error as RpcError);
		}
	}

	async function focusNetwork(networkName: string) {
		try {
			await snifferClient.focusNetwork({ ssid: networkName });
			getFocusState();
		} catch (error) {
			displayError(error as RpcError);
		}
	}

	async function stopFocus() {
		try {
			await snifferClient.stopFocus({});
			getFocusState();
		} catch (error) {
			displayError(error as RpcError);
		}
	}

	async function providePassword(networkName: string, passwd: string) {
		try {
			await snifferClient.providePassword({ ssid: networkName, passwd });
			// You might want to update some state or trigger another action here
		} catch (error) {
			displayError(error as RpcError);
		}
	}

	async function getIgnoredNetworks() {
		try {
			const response = await snifferClient.getIgnoredNetworks({});
			console.log("Ignored networks:", response.response);
			// Handle the ignored networks as needed
		} catch (error) {
			displayError(error as RpcError);
		}
	}

	async function loadRecording(fileName: string) {
		try {
			const call = snifferClient.loadRecording({ name: fileName });
			for await (const packet of call.responses) {
				console.log("Received packet:", packet);
				// Handle each packet as it comes in
			}
		} catch (error) {
			displayError(error as RpcError);
		}
	}

	async function saveDecryptedTraffic(networkName: string) {
		try {
			await snifferClient.saveDecryptedTraffic({ ssid: networkName });
			console.log("Decrypted traffic saved for network:", networkName);
		} catch (error) {
			displayError(error as RpcError);
		}
	}
</script>

<style>
	.container {
	  display: flex;
	  margin-left:0%;
	  margin-right:0%;
	  flex: 1;
	  height: calc(100vh - 60px);
	  padding: 0;
	}
  
	.sidebar {
	  width: 200px;
	  background-color: #2F2733;
	  display: flex;
	  flex-direction: column;
	  padding: 10px;
	  align-items: center;
	}
  
	.sidebar button {
	  background-color: #444;
	  color: white;
	  border: none;
	  padding: 10px;
	  margin-bottom: 10px;
	  cursor: pointer;
	  border-radius: 5px;
	  width: 100%;
	  text-align: left;
	}
  
	.sidebar button:hover {
	  background-color: #555;
	}
  
	.sidebar img {
	  width: 100%;
	  margin-bottom: 20px;
	}
  
	.content {
	  flex: 1;
	  padding: 20px;
	  overflow-y: auto;
	  background-color: #2F2733;
	  display: flex;
	  flex-direction: column;
	  justify-content: center;
	  align-items: center;
	}
  
	.table-container {
	  flex: 1;
	  background-color: white;
	  color: black;
	  border-radius: 5px;
	  padding: 10px;
	  overflow: auto;
	  width: 80%;
	  height: 80%;
	}
  
	.controls {
	  display: flex;
	  flex-direction: column;
	  padding: 10px;
	  width: 200px;
	  background-color: #2F2733;
	}
  
	.controls button {
	  background-color: #444;
	  color: white;
	  border: none;
	  padding: 10px;
	  margin-bottom: 10px;
	  cursor: pointer;
	  border-radius: 5px;
	}
  
	.controls button:hover {
	  background-color: #555;
	}
  
	.controls input {
	  padding: 10px;
	  margin-bottom: 10px;
	  border-radius: 5px;
	  border: 1px solid #444;
	  color: black;
	}

	table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 20px;
    }

    th, td {
        border: 1px solid #ddd;
        padding: 8px;
        text-align: left;
    }

    th {
        background-color: #f2f2f2;
        color: black;
    }

    tr:nth-child(even) {
        background-color: #f9f9f9;
    }

    tr:hover {
        background-color: #f5f5f5;
    }

	.controls {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .network-list {
    display: flex;
    flex-direction: column;
    gap: 5px;
    max-height: 200px;
    overflow-y: auto;
    border: 1px solid #ccc;
    padding: 10px;
    margin-top: 10px;
  }

  </style>
  
  <div class="container">
	<div class="sidebar">
		<img src="src/images/yarilo.png" alt="YARILO Logo">
		<button on:click={getFocusState}>GetFocusState</button>
		<button on:click={stopFocus}>StopFocus</button>
		<button on:click={getIgnoredNetworks}>GetIgnoredNetworks</button>
		<button on:click={() => loadRecording(prompt('Enter file name') || '')}>LoadRecording</button>
		<button on:click={() => saveDecryptedTraffic(focusedNetwork?.name || '')}>SaveDecryptedTraffic</button>
	</div>
	<div class="content">
        <div class="table-container">
            {#if focusedNetwork}
                <h2>Focused Network: {focusedNetwork.name}</h2>
                <table>
                    <tr>
                        <th>BSSID</th>
                        <td>{focusedNetwork.bssid}</td>
                    </tr>
                    <tr>
                        <th>Channel</th>
                        <td>{focusedNetwork.channel.toString()}</td>
                    </tr>
                    <tr>
                        <th>Encrypted Packets</th>
                        <td>{focusedNetwork.encryptedPacketCount.toString()}</td>
                    </tr>
                    <tr>
                        <th>Decrypted Packets</th>
                        <td>{focusedNetwork.decryptedPacketCount.toString()}</td>
                    </tr>
                </table>

                <h3>Clients:</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Address</th>
                            <th>Decrypted</th>
                            <th>Handshake</th>
                            <th>Can Decrypt</th>
                        </tr>
                    </thead>
                    <tbody>
                        {#each focusedNetwork.clients as client}
                            <tr>
                                <td>{client.addr}</td>
                                <td>{client.isDecrypted ? 'Yes' : 'No'}</td>
                                <td>{client.handshakeNum.toString()}</td>
                                <td>{client.canDecrypt ? 'Yes' : 'No'}</td>
                            </tr>
                        {/each}
                    </tbody>
                </table>

                <h3>Recent Packets:</h3>
                <table>
                    <thead>
                        <tr>
                            <th>From</th>
                            <th>To</th>
                            <th>Protocol</th>
                            <th>Data</th>
                        </tr>
                    </thead>
                    <tbody>
                        {#each packets as packet}
                            <tr>
                                <td>{packet.from?.mACAddress} ({packet.from?.iPv4Address}:{packet.from?.port})</td>
                                <td>{packet.to?.mACAddress} ({packet.to?.iPv4Address}:{packet.to?.port})</td>
                                <td>{packet.protocol}</td>
                                <td>{new TextDecoder().decode(packet.data).substring(0, 50)}...</td>
                            </tr>
                        {/each}
                    </tbody>
                </table>
            {:else}
                <p>No network focused. Select a network to view details.</p>
            {/if}
        </div>
    </div>
	<div class="controls">
		<button on:click={getAllAccessPoints}>GetAllAccessPoints</button>
		{#if showNetworkList && networkList}
		  <div class="network-list">
			{#each networkList.names as network}
			  <label>
				<input 
				  type="checkbox" 
				  checked={selectedNetworks.has(network)} 
				  on:change={() => toggleNetworkSelection(network)}
				/>
				{network}
			  </label>
			{/each}
		  </div>
		{/if}
        <button on:click={() => getAccessPoint(prompt('Enter network name') || '')}>GetAccessPoint</button>
        <input type="text" placeholder="Password" bind:value={password}>
        <button on:click={() => providePassword(focusedNetwork?.name || '', password)}>ProvidePassword</button>
        <button on:click={() => focusNetwork(focusedNetwork?.name || '')}>FocusNetwork</button>
    </div>
</div>

{#if errMsg}
	<Error message={errMsg} />
{/if}