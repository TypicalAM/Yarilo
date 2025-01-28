<script lang="ts">
	import VirtualList from '@sveltejs/svelte-virtual-list';
	import type { Packet } from '../proto/service';
	import PacketDetails from './PacketDetails.svelte';

	export let packets: Packet[] = [];
	export let expandedPacketId: number | null = null;
	export let onPacketClick: (index: number) => void;
	export let getPacketType: (packet: Packet) => string;
	export let getPacketDetails: (packet: Packet) => string;
	export let formatTime: (timestamp?: { seconds?: bigint }) => string;

	$: rows = packets.map((packet, index) => ({
		packet,
		index,
		isExpanded: expandedPacketId === index
	}));

	function getPacketTypeClass(type: string): string {
		switch (type) {
			case 'TCP':
				return 'text-blue-600 bg-blue-50';
			case 'UDP':
				return 'text-purple-600 bg-purple-50';
			case 'DNS':
				return 'text-amber-600 bg-amber-50';
			case 'DHCP':
			case 'DHCPv6':
				return 'text-pink-600 bg-pink-50';
			case 'ARP':
				return 'text-green-600 bg-green-50';
			case 'ICMP':
			case 'ICMPv6':
				return 'text-orange-600 bg-orange-50';
			case 'IP':
				return 'text-indigo-600 bg-indigo-50';
			case 'IPv6':
				return 'text-cyan-600 bg-cyan-50';
			case 'RAW':
				return 'text-gray-600 bg-gray-50';
			default:
				return 'text-gray-600 bg-gray-50';
		}
	}
</script>

<div class="h-full overflow-hidden rounded-lg border">
	<div
		class="grid grid-cols-[100px_200px_200px_100px_1fr] bg-gray-100 px-4 py-2 text-sm font-medium"
	>
		<div>Time</div>
		<div>Source</div>
		<div>Destination</div>
		<div>Type</div>
		<div>Details</div>
	</div>

	<div class="h-[calc(100%-40px)] overflow-auto">
		<VirtualList items={rows} let:item={row} itemHeight={40}>
			<div class="flex flex-col">
				<div
					class="flex h-10 cursor-pointer items-center px-4 hover:bg-gray-50"
					class:bg-gray-50={row.isExpanded}
					on:click={() => onPacketClick(row.index)}
				>
					<div class="w-[100px] text-sm text-gray-600">
						{formatTime(row.packet.captureTime)}
					</div>
					<div class="w-[200px] truncate font-mono text-sm">
						{row.packet.src}
					</div>
					<div class="w-[200px] truncate font-mono text-sm">
						{row.packet.dst}
					</div>
					<div class="w-[100px] text-sm">
						<span
							class={`rounded-full px-2 py-0.5 text-xs ${getPacketTypeClass(getPacketType(row.packet))}`}
						>
							{getPacketType(row.packet)}
						</span>
					</div>
					<div class="flex-1 truncate text-sm text-gray-600">
						{getPacketDetails(row.packet)}
					</div>
				</div>
				{#if row.isExpanded}
					<div class="border-t border-gray-100 px-4">
						<PacketDetails packet={row.packet} />
					</div>
				{/if}
			</div>
		</VirtualList>
	</div>
</div>
