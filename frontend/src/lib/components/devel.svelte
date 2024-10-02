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
		type RecordingsList,
		type Packet,
		type IP,
		type IPv6,
		type UDP,
		ICMP_Type,
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

	function formatDhcpMessage(dhcpMessage: any) {
		// Mapping message types to human-readable descriptions
		const messageTypeMap = {
			'1': 'DHCP Discover',
			'2': 'DHCP Offer',
			'3': 'DHCP Request',
			'4': 'DHCP Decline',
			'5': 'DHCP ACK',
			'6': 'DHCP NAK',
			'7': 'DHCP Release',
			'8': 'DHCP Inform'
		};

		console.log(dhcpMessage);
		// Get the message type description, fallback to "Unknown" if not recognized
		const messageType =
			messageTypeMap[dhcpMessage.messageType] ||
			`Unknown Message Type (${dhcpMessage.messageType})`;

		// Format the transaction ID to hexadecimal with "0x" prefix
		const transactionId = dhcpMessage.transactionId
			? `0x${parseInt(dhcpMessage.transactionId).toString(16)}`
			: 'Unknown Transaction ID';

		// Construct the Wireshark-like string
		return `${messageType} - Transaction ID ${transactionId}`;
	}

	function formatIpMessage(ipPacket: IP) {
		// Map protocol numbers to human-readable names
		const protocolMap = {
			1: 'ICMP',
			2: 'IGMP',
			6: 'TCP',
			17: 'UDP',
			47: 'GRE',
			50: 'IPsec ESP',
			132: 'SCTP'
		};

		// Get the protocol name or fallback to the protocol number if not recognized
		const protocolName =
			protocolMap[ipPacket.protocol] || `Unknown Protocol (${ipPacket.protocol})`;

		// Construct a Wireshark-like string for the IP packet
		let msg = `IP Packet - Source: ${ipPacket.sourceAddress}, Destination: ${ipPacket.destinationAddress}, Protocol: ${protocolName}, TTL: ${ipPacket.ttl}, Total Length: ${ipPacket.totalLength} bytes `;
		switch (ipPacket.next.oneofKind) {
			case 'icmp':
				let icmp_msg = 'ICMP ';
				switch (ipPacket.next.icmp.type) {
					case ICMP_Type.ECHO_REPLY:
						icmp_msg = icmp_msg.concat('Echo Reply ');
						break;
					case ICMP_Type.DESTINATION_UNREACHABLE:
						icmp_msg = icmp_msg.concat('Destination Unreachable ');
						break;

					case ICMP_Type.ECHO_REQUEST:
						icmp_msg = icmp_msg.concat('Echo Request ');
						break;

					case ICMP_Type.TIME_EXCEEDED:
						msg = icmp_msg.concat('Time Exceeded ');
						break;

					case ICMP_Type.OTHER:
				}
				icmp_msg += ` - Code ${ipPacket.next.icmp.code}`;
				msg += icmp_msg;
				break;
			case 'tcp':
				msg += formatTcpMessage(ipPacket.next.tcp);
				break;
			case 'udp':
				msg += formatUdpMessage(ipPacket.next.udp);
				break;
			default:
				break;
		}

		return msg;
	}

	function formatIpv6Message(ipv6Packet: IPv6) {
		// Map protocol numbers to human-readable names
		const protocolMap = {
			1: 'ICMPv4',
			58: 'ICMPv6', // ICMP for IPv6
			6: 'TCP',
			17: 'UDP',
			41: 'IPv6 encapsulation',
			43: 'Routing Header',
			44: 'Fragment Header',
			50: 'IPsec ESP',
			51: 'IPsec AH',
			132: 'SCTP'
		};

		// Get the protocol name or fallback to the protocol number if not recognized
		const protocolName =
			protocolMap[ipv6Packet.nextHeader] || `Unknown Protocol (${ipv6Packet.nextHeader})`;

		// Construct a Wireshark-like string for the IPv6 packet
		let msg = `IPv6 Packet - Source: ${ipv6Packet.sourceAddress}, Destination: ${ipv6Packet.destinationAddress}, Protocol: ${protocolName}, Hop Limit: ${ipv6Packet.hopLimit}, Payload Length: ${ipv6Packet.payloadLength} bytes `;
		switch (ipv6Packet.next.oneofKind) {
			case 'icmpv6':
				msg += formatIcmpv6Message(ipv6Packet.next.icmpv6);
				break;
			case 'tcp':
				msg += formatTcpMessage(ipv6Packet.next.tcp);
				break;
			case 'udp':
				msg += formatUdpMessage(ipv6Packet.next.udp);
				break;
			default:
				break;
		}

		return msg;
	}

	function formatTcpMessage(tcpPacket: any) {
		// Construct flag string based on boolean fields
		let flags = [];
		if (tcpPacket.syn) flags.push('SYN');
		if (tcpPacket.ack) flags.push('ACK');
		if (tcpPacket.fin) flags.push('FIN');

		const flagString = flags.length > 0 ? flags.join(', ') : 'No flags set';

		// Construct a Wireshark-like string for the TCP packet
		return (
			`TCP Packet - Source Port: ${tcpPacket.sourcePort}, Destination Port: ${tcpPacket.destinationPort}, ` +
			`Sequence Number: ${tcpPacket.sequenceNumber}, Acknowledgment Number: ${tcpPacket.acknowledgmentNumber}, ` +
			`Window Size: ${tcpPacket.windowSize}, Flags: ${flagString}, Payload Size: ${tcpPacket.payload.length} bytes`
		);
	}

	function formatUdpMessage(udpPacket: UDP) {
		// Construct a Wireshark-like string for the UDP packet
		let msg = `UDP Packet - Source Port: ${udpPacket.sourcePort}, Destination Port: ${udpPacket.destinationPort}, `;
		switch (udpPacket.next.oneofKind) {
			case 'dns':
				const dns = udpPacket.next.dns;
				msg += `DNS ID: ${dns.id}, ${dns.qr ? 'Response' : 'Query'}, Questions: [${dns.questions.map((q) => `${q.name} (Type ${q.type})`).join(', ')}], Answers: [${dns.answers.map((a) => `${a.name} (Type ${a.type}, Data: ${a.data})`).join(', ')}]`;
				break;

			case 'dhcp':
				const dhcp = udpPacket.next.dhcp;
				msg += formatDhcpMessage(dhcp);
				break;

			case 'dhcpv6':
				const dhcpv6 = udpPacket.next.dhcpv6;
				msg += formatDhcpv6Message(dhcpv6);
				break;
			default:
				break;
		}

		return msg;
	}

	function formatDhcpv6Message(dhcpv6Packet: any) {
		// Format the options
		const optionsFormatted = dhcpv6Packet.options
			.map((option: any) => {
				return `Option Code: ${option.optionCode}, Length: ${option.optionLength}, Data Size: ${option.optionData.length} bytes`;
			})
			.join('; ');

		// Construct a Wireshark-like string for the DHCPv6 packet
		return (
			`DHCPv6 Packet - Message Type: ${dhcpv6Packet.messageType}, Transaction ID: ${dhcpv6Packet.transactionId}, ` +
			`Options: [${optionsFormatted}]`
		);
	}

	function formatIcmpv6Message(icmpv6Packet: any) {
		// Map the Type enum to human-readable names
		const typeMap = {
			0: 'NONE',
			128: 'ECHO_REQUEST',
			129: 'ECHO_REPLY',
			1: 'DESTINATION_UNREACHABLE',
			2: 'PACKET_TOO_BIG',
			3: 'TIME_EXCEEDED',
			4: 'PARAMETER_PROBLEM',
			135: 'NEIGHBOR_SOLICITATION',
			136: 'NEIGHBOR_ADVERTISEMENT'
		};

		// Get the type name or fallback to the number if not recognized
		const typeName = typeMap[icmpv6Packet.type] || `Unknown Type (${icmpv6Packet.type})`;

		// Construct a Wireshark-like string for the ICMPv6 packet
		return `ICMPv6 Packet - Type: ${typeName}, Code: ${icmpv6Packet.code}, Checksum: ${icmpv6Packet.checksum}`;
	}

	const snifferListRet = async () => {
		await ensureConnected();
		let dupa = $client.snifferList({});
		return (await Promise.resolve(dupa.response)).sniffers;
	};

	const getAccessPointDetails = (ap: string) => async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid;
		let data = await $client.getAccessPoint({ snifferUuid: uuid, ssid: ap });
		console.log(data.response);
	};

	const providePassword = (ap: string) => async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid;
		let data = await $client.providePassword({ snifferUuid: uuid, ssid: ap, passwd: password });
		console.log(data.response);
	};

	const deauth = (ap: string, client: string) => async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid;
		let data = await $client.deauthNetwork({
			snifferUuid: uuid,
			network: { snifferUuid: uuid, ssid: ap },
			userAddr: client
		});
		console.log(data.response);
	};

	const ignoreNetwork = (ap: string) => async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid;
		let data = await $client.ignoreNetwork({
			snifferUuid: uuid,
			ssid: ap
		});
		console.log(data.response);
	};

	const getIgnoredNetworks = async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid;
		let data = await $client.getIgnoredNetworks({ uuid: uuid });
		console.log(data.response);
	};

	const createRecording = (ap: string, decrypted: boolean) => async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid;
		let data = await $client.recordingCreate({
			snifferUuid: uuid,
			singularAp: ap !== '',
			ssid: ap,
			dataLink: decrypted ? DataLinkType.ETH2 : DataLinkType.DOT11
		});
		console.log(data.response);
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

	const getDecryptedPackets = (ap: string) => async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid;
		let data = $client.getDecryptedPackets({ snifferUuid: uuid, ssid: ap });
		data.responses.onMessage((message: Packet) => {
			printPacket(message);
		});

		data.responses.onError((reason: Error) => {
			console.log(`Get derypted packets error: ${reason}`);
		});

		data.responses.onComplete(() => {
			console.log('Get derypted packets finished');
		});
	};

	const printPacket = (pkt: Packet) => {
		let msg = `Packet from ${pkt.src} to ${pkt.dst}: `;
		switch (pkt.data.oneofKind) {
			case 'raw':
				msg = msg.concat(`RAW: ${pkt.data.raw.payload}`);
				break;

			case 'arp':
				msg = msg.concat(
					`ARP from ${pkt.data.arp.senderIpAddress} (${pkt.data.arp.senderMacAddress}) to ${pkt.data.arp.targetIpAddress} ${pkt.data.arp.targetMacAddress}`
				);
				break;

			case 'ip':
				const ip = pkt.data.ip;
				msg += formatIpMessage(ip);
				break;

			case 'ipv6':
				const ipv6 = pkt.data.ipv6;
				msg += formatIpv6Message(ipv6);
				break;
		}

		console.log(msg);
	};

	const loadRecording = (filename: string) => async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid;
		let data = $client.loadRecording({ snifferUuid: uuid, name: filename });
		data.responses.onMessage((message: Packet) => {
			printPacket(message);
		});

		data.responses.onError((reason: Error) => {
			console.log(`Load recording error: ${reason}`);
		});

		data.responses.onComplete(() => {
			console.log('Load recording finished');
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

	const netSnifferCreate = (netname: string) => async () => {
		await ensureConnected();
		let result = await $client.snifferCreate({
			isFileBased: false,
			netIfaceName: netname,
			filename: ''
		});
		console.log('Created a sniffer', result.response.uuid);
	};

	// Destroy a sniffer instance
	const snifferDestroy = async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid; // xd
		await $client.snifferDestroy({ uuid: uuid });
		console.log('Sniffer destroyed');
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
	<Button on:click={loadRecording('dhcp.pcapng')}>Load recording</Button>
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
