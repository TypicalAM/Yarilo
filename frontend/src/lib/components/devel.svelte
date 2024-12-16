<script lang="ts">
	export let errMsg: string | null;
	export let networkList: string[] = [];
	export let focusedNetwork: string | null;

	const mynetName = 'Schronisko Bielsko Biala';
	const mynet = '68:d4:82:86:34:dd'; // Schronisko address
	const myclient = 'de:4e:d5:b2:3d:2e';
	const myfilename = 'test.pcap';
	const mynetname = 'wlp5s0f3u2';

	let password: string = '';

	import type { RpcError, FinishedUnaryCall } from '@protobuf-ts/runtime-rpc';
	import {
		type Packet,
		type IP,
		type IPv6,
		type UDP,
		type LogEntry,
		ICMP_Type,
		DataLinkType
	} from '$lib/proto/service';
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

	// Sniffer related

	// Create a sniffer instance
	const fileSnifferCreate = (filename: string) => async () => {
		await ensureConnected();
		let result = await $client.snifferCreate({
			isFileBased: true,
			netIfaceName: '',
			recordingUuid: 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa'
		});
		console.log('Created a sniffer', result.response.snifferUuid);
	};

	const netSnifferCreate = (netname: string) => async () => {
		await ensureConnected();
		let result = await $client.snifferCreate({
			isFileBased: false,
			netIfaceName: netname,
			recordingUuid: ''
		});
		console.log('Created a sniffer', result.response.snifferUuid);
	};

	// Destroy a sniffer instance
	const snifferDestroy = async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid; // xd
		await $client.snifferDestroy({ snifferUuid: uuid });
		console.log('Sniffer destroyed');
	};

	// List active sniffers
	const snifferList = async () => {
		await ensureConnected();
		let sniffers = (await $client.snifferList({}).response).sniffers;
		console.log('Sniffer list:', sniffers);
	};

	const snifferListRet = async () => {
		await ensureConnected();
		let test = await $client.snifferList({});
		return test.response.sniffers;
	};

	// End of sniffer related

	// Start of access point related

	// Get a list of available access points (networks)
	const accessPointList = async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid;
		let netList = (await $client.accessPointList({ snifferUuid: uuid }).response).nets;
		console.log('Networks list:', netList);
	};

	const accessPointGet = (bssid: string) => async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid;
		let netDetails = (await $client.accessPointGet({ snifferUuid: uuid, bssid: bssid }).response)
			.ap;
		console.log('Access Point details:', netDetails);
	};

	const accessPointProvidePassword = (bssid: string) => async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid;
		let response = await $client.accessPointProvidePassword({
			snifferUuid: uuid,
			bssid: bssid,
			password: password
		}).response;
		console.log('Decryption state:', response);
	};

	const accessPointGetDeryptedStream = (bssid: string, payload: boolean) => async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid;
		let data = $client.accessPointGetDeryptedStream({
			snifferUuid: uuid,
			bssid: bssid,
			includePayload: payload
		});
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

	const accessPointDeauth = (bssid: string) => async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid;
		let data = await $client.accessPointDeauth({
			snifferUuid: uuid,
			bssid: bssid
		});

		console.log('Deauth state:', data.response);
	};

	const accessPointDeauthClient = (bssid: string, clientAddr: string) => async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid;
		let data = await $client.accessPointDeauthClient({
			snifferUuid: uuid,
			bssid: bssid,
			clientAddr: clientAddr
		});

		console.log('Deauth client state:', data.response);
	};

	const accessPointGetHash = (bssid: string, clientAddr: string) => async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid;
		let data = await $client.accessPointGetHash({
			snifferUuid: uuid,
			bssid: bssid,
			clientAddr: clientAddr
		});

		console.log('Access point HC22000 hash:', data.response);
	};

	const accessPointIgnoreByAddress = (bssid: string) => async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid;
		let data = await $client.accessPointIgnore({
			snifferUuid: uuid,
			bssid: bssid,
			useSsid: false,
			ssid: ''
		});

		console.log('Ignore state:', data.response);
	};

	const accessPointIgnoreByName = (ssid: string) => async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid;
		let data = await $client.accessPointIgnore({
			snifferUuid: uuid,
			bssid: '',
			useSsid: true,
			ssid: ssid
		});

		console.log('Ignore state:', data.response);
	};

	const accessPointListIgnored = async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid;
		let data = await $client.accessPointListIgnored({ snifferUuid: uuid });
		console.log('Ignored networks:', data.response);
	};

	const accessPointCreateRecording = (bssid: string, raw: boolean) => async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid;
		let data = await $client.accessPointCreateRecording({
			snifferUuid: uuid,
			name: 'My little recording',
			bssid: bssid,
			raw: raw
		});

		console.log('AP Recording create:', data.response);
	};

	// End of access point related

	// Focus related

	const focusStart = (bssid: string) => async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid;
		let data = await $client.focusStart({
			snifferUuid: uuid,
			bssid: bssid
		});

		console.log('Focus start:', data.response);
	};

	const focusGetActive = async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid;
		let data = await $client.focusGetActive({
			snifferUuid: uuid
		});

		console.log('Focus get active:', data.response);
	};

	const focusStop = async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid;
		let data = await $client.focusStop({
			snifferUuid: uuid
		});

		console.log('Focus stop:', data.response);
	};

	// End of focus related

	// Recording related

	const recordingCreate = (raw: boolean) => async () => {
		await ensureConnected();
		let uuid = (await snifferListRet())[0].uuid;
		let data = await $client.recordingCreate({
			snifferUuid: uuid,
			name: 'My little recording',
			raw: raw
		});

		console.log('Recording create:', data.response);
	};

	const recordingList = async () => {
		await ensureConnected();
		let response = await $client.recordingList({
			allowedTypes: [DataLinkType.RAW80211]
		}).response;

		console.log('Recording list:', response);
	};

	const recordingLoadDecrypted = (filename: string, includePayload: boolean) => async () => {
		await ensureConnected();
		let data = $client.recordingLoadDecrypted({
			uuid: 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',
			includePayload: includePayload
		});
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

	// End of recording related

	// Miscellaneous

	const networkInterfaceList = async () => {
		await ensureConnected();
		let response = await $client.networkInterfaceList({}).response;

		console.log('Network interafce list:', response.ifaces);
	};

	const logGetStream = async () => {
		await ensureConnected();
		let data = $client.logGetStream({});

		data.responses.onMessage((message: LogEntry) => {
			console.log('Log entry: ', message);
		});

		data.responses.onError((reason: Error) => {
			console.log('Load recording error:', reason);
		});

		data.responses.onComplete(() => {
			console.log('Load recording finished');
		});
	};

	const batteryGetLevel = async () => {
		await ensureConnected();
		let response = await $client.batteryGetLevel({}).response;
		console.log('Battery get level:', response);
	};

	// End of miscellaneous

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
</script>

<Input type="password" bind:value={password} placeholder="Password!" />

<div>
	<h1>Sniffers</h1>
	<Button on:click={fileSnifferCreate(myfilename)}>Create file Sniffer</Button>
	<Button on:click={netSnifferCreate(mynetname)}>Create network Sniffer</Button>
	<Button on:click={snifferDestroy}>Destroy Sniffer</Button>
	<Button on:click={snifferList}>List Active Sniffers</Button>
</div>

<div>
	<h1>Access Points</h1>
	<Button on:click={accessPointList}>List APs</Button>
	<Button on:click={accessPointGet(mynet)}>Network details</Button>
	<Button on:click={accessPointProvidePassword(mynet)}>Confirm the password</Button>
	<Button on:click={accessPointGetDeryptedStream(mynet, false)}
		>Get Decrypted Traffic (No Payload)</Button
	>
	<Button on:click={accessPointGetDeryptedStream(mynet, true)}
		>Get Decrypted Traffic (Payload)</Button
	>
	<Button on:click={accessPointDeauth(mynet)}>Deauthenticate the whole network</Button>
	<Button on:click={accessPointDeauthClient(mynet, myclient)}
		>Deauthenticate a specific client</Button
	>
	<Button on:click={accessPointGetHash(mynet, myclient)}>Extract hashcat cracking info</Button>
	<Button on:click={accessPointIgnoreByAddress(mynet)}>Ignore the network (by address)</Button>
	<Button on:click={accessPointIgnoreByName(mynetName)}>Ignore the network (by name)</Button>
	<Button on:click={accessPointListIgnored}>Get Ignored</Button>
	<Button on:click={accessPointCreateRecording(mynet, true)}>Create recording (Raw)</Button>
	<Button on:click={accessPointCreateRecording(mynet, false)}>Create recording (Decrypted)</Button>
</div>

<div>
	<h1>Focus</h1>
	<Button on:click={focusStart(mynet)}>Start focusing</Button>
	<Button on:click={focusGetActive}>Get currently focused</Button>
	<Button on:click={focusStop}>Stop focusing</Button>
</div>

<div>
	<h1>Recordings</h1>
	<Button on:click={recordingCreate(true)}>Create recording (Raw)</Button>
	<Button on:click={recordingCreate(false)}>Create recording (Decrypted)</Button>
	<Button on:click={recordingList}>Get available recordings</Button>
	<Button on:click={recordingLoadDecrypted('dhcp.pcapng', false)}
		>Get Decrypted Traffic (No Payload)</Button
	>
	<Button on:click={recordingLoadDecrypted('dhcp.pcapng', true)}
		>Get Decrypted Traffic (Payload)</Button
	>
</div>

<div>
	<h1>Misc</h1>
	<Button on:click={networkInterfaceList}>Get network interfaces</Button>
	<Button on:click={logGetStream}>Get Log Stream</Button>
	<Button on:click={batteryGetLevel}>Get Battery Percentage</Button>
</div>

<style>
	* {
		margin: 10px !important;
	}
</style>
