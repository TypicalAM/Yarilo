<script lang="ts">
	import type { Packet } from '../proto/service';
	export let packet: Packet;

	type PacketProcessor = (data: any) => Record<string, string>;

	const protocolProcessors: Record<string, PacketProcessor> = {
		arp: (data) => ({
			'Sender IP': data.senderIpAddress,
			'Sender MAC': data.senderMacAddress,
			'Target IP': data.targetIpAddress,
			'Target MAC': data.targetMacAddress
		}),
		icmp: (data) => ({
			Type: data.type || 'Unknown',
			Code: data.code || '0'
		}),
		icmpv6: (data) => ({
			Type: data.type || 'Unknown',
			Code: data.code || '0',
			Checksum: data.checksum || 'Unknown'
		}),
		ip: (data) => ({
			'Source Address': data.sourceAddress,
			'Destination Address': data.destinationAddress,
			TTL: `${data.ttl}`,
			'Total Length': `${data.totalLength}`,
			'Next Protocol': data.next?.oneofKind || 'None',
			...getNestedDetails(data.next)
		}),
		ipv6: (data) => ({
			'Source Address': data.sourceAddress,
			'Destination Address': data.destinationAddress,
			'Hop Limit': `${data.hopLimit}`,
			'Next Header': `${data.nextHeader}`,
			...getNestedDetails(data.next)
		}),
		tcp: (data) => ({
			'Source Port': `${data.sourcePort}`,
			'Destination Port': `${data.destinationPort}`,
			'Sequence Number': `${data.sequenceNumber}`,
			'Acknowledgment Number': `${data.acknowledgmentNumber}`,
			Flags: `${data.syn ? 'SYN ' : ''}${data.ack ? 'ACK ' : ''}${data.fin ? 'FIN' : ''}`
		}),
		udp: (data) => ({
			'Source Port': `${data.sourcePort}`,
			'Destination Port': `${data.destinationPort}`,
			'Next Protocol': data.next?.oneofKind || 'None',
			...getNestedDetails(data.next)
		}),
		dns: (data) => ({
			ID: `${data.id}`,
			'Query/Response': data.qr ? 'Response' : 'Query',
			Questions: data.questions?.map((q) => `${q.name} (Type: ${q.type})`).join(', ') || 'None',
			Answers:
				data.answers?.map((a) => `${a.name} -> ${a.data} (Type: ${a.type})`).join(', ') || 'None'
		}),
		dhcp: (data) => ({
			'Message Type': `${data.messageType}`,
			'Transaction ID': `${data.transactionId}`,
			'Client IP': data.clientIpAddress,
			'Server IP': data.serverIpAddress,
			'Client MAC': data.clientMacAddress
		}),
		dhcpv6: (data) => ({
			'Message Type': `${data.messageType}`,
			'Transaction ID': `${data.transactionId}`,
			Options:
				data.options?.map((opt) => `Option ${opt.optionCode}: ${opt.optionData}`).join(', ') ||
				'None'
		}),
		default: () => ({
			Details: 'Unknown protocol or no details available.'
		})
	};

	function getPacketDetails(packet: Packet): Record<string, string> {
		const protocol = packet.data.oneofKind;
		const processor = protocolProcessors[protocol] || protocolProcessors.default;

		return processor(packet.data[protocol]);
	}

	function getNestedDetails(next: any): Record<string, string> {
		if (!next || !next.oneofKind) return {};
		const nestedProcessor = protocolProcessors[next.oneofKind] || protocolProcessors.default;
		return nestedProcessor(next[next.oneofKind]);
	}

	let packetDetails = getPacketDetails(packet);
</script>

<div class="bg-muted rounded-md p-4">
	<h3 class="text-foreground mb-2 text-lg font-medium">Packet Details</h3>
	<div class="grid grid-cols-2 gap-y-2">
		{#each Object.entries(packetDetails) as [key, value]}
			<div class="text-muted-foreground text-sm font-medium">{key}:</div>
			<div class="text-foreground text-sm">{value}</div>
		{/each}
	</div>
</div>
