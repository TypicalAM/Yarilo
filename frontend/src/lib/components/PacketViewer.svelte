<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { get } from 'svelte/store';
	import {
		client,
		activeSnifferId,
		selectedNetwork,
		isLoading,
		notifications,
		packets,
		isStreaming
	} from '../stores';
	import { Button } from './ui/button';
	import { Input } from './ui/input';
	import type { Packet } from '../proto/service';
	import RecordingLoaderModal from './RecordingLoaderModal.svelte';
	import RecordingSaveModal from './RecordingSaveModal.svelte';
	import VirtualizedPacketViewer from './VirtualizedPacketViewer.svelte';
	import { Protocol, UDP, IP, IPv6 } from '../proto/service';

	// SVG Icons
	const IconArrowUp = `<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
        <path fill-rule="evenodd" d="M3.293 9.707a1 1 0 010-1.414l6-6a1 1 0 011.414 0l6 6a1 1 0 01-1.414 1.414L11 5.414V17a1 1 0 11-2 0V5.414L4.707 9.707a1 1 0 01-1.414 0z" clip-rule="evenodd" />
    </svg>`;

	const IconArrowDown = `<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
        <path fill-rule="evenodd" d="M16.707 10.293a1 1 0 010 1.414l-6 6a1 1 0 01-1.414 0l-6-6a1 1 0 111.414-1.414L9 14.586V3a1 1 0 012 0v11.586l4.293-4.293a1 1 0 011.414 0z" clip-rule="evenodd" />
    </svg>`;

	const IconArrowUpDown = `<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
        <path fill-rule="evenodd" d="M3.293 7.293a1 1 0 011.414 0L10 12.586l5.293-5.293a1 1 0 111.414 1.414l-6 6a1 1 0 01-1.414 0l-6-6a1 1 0 010-1.414zm0-4a1 1 0 011.414 0L10 8.586l5.293-5.293a1 1 0 111.414 1.414l-6 6a1 1 0 01-1.414 0l-6-6a1 1 0 010-1.414z" clip-rule="evenodd" />
    </svg>`;

	const IconSearch = `<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
        <path fill-rule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clip-rule="evenodd" />
    </svg>`;

	const IconFilter = `<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
        <path fill-rule="evenodd" d="M3 3a1 1 0 011-1h12a1 1 0 011 1v3a1 1 0 01-.293.707L12 11.414V15a1 1 0 01-.293.707l-2 2A1 1 0 018 17v-5.586L3.293 6.707A1 1 0 013 6V3z" clip-rule="evenodd" />
    </svg>`;

	let packetList: Packet[] = [];
	let filteredAndSortedPackets: Packet[] = [];
	let streamController: AbortController | null = null;
	let showRecordingLoader = false;
	let showRecordingSaveModal = false;
	let expandedPacketId: number | null = null;
	let sortField: SortField = 'time';
	let sortDirection: SortDirection = 'desc';
	let searchQuery = '';
	let virtualListRef: { scrollToTop?: () => void } | undefined;
	let selectedProtocols: Set<string> = new Set();
	let availableProtocols: string[] = [
		'TCP',
		'UDP',
		'ARP',
		'ICMP',
		'ICMPv6',
		'DNS',
		'DHCP',
		'DHCPv6',
		'IP',
		'IPv6',
		'RAW'
	];
	type SortField = 'time' | 'source' | 'destination' | 'type' | 'size';
	type SortDirection = 'asc' | 'desc';

	// Reactive packets actualization
	$: {
		if ($packets) {
			packetList = [...$packets];
		}
	}
	// Sorting after every new packets
	$: {
		filteredAndSortedPackets = filterAndSortPackets(packetList);
	}

	// Looking for filters changes
	$: {
		if (searchQuery !== undefined || selectedProtocols) {
			filteredAndSortedPackets = filterAndSortPackets(packetList);
			if (virtualListRef?.scrollToTop) {
				virtualListRef.scrollToTop();
			}
		}
	}

	$: {
		if (sortField || sortDirection) {
			filteredAndSortedPackets = filterAndSortPackets(packetList);
		}
	}

	function filterAndSortPackets(packets: Packet[]): Packet[] {
		let filtered = [...packets];

		// Filter by protocols
		if (selectedProtocols.size > 0) {
			filtered = filtered.filter((packet) => {
				const type = getPacketType(packet);
				return selectedProtocols.has(type);
			});
		}

		// Search
		if (searchQuery) {
			const query = searchQuery.toLowerCase();
			filtered = filtered.filter((packet) => {
				return (
					packet.src.toLowerCase().includes(query) ||
					packet.dst.toLowerCase().includes(query) ||
					getPacketDetails(packet).toLowerCase().includes(query)
				);
			});
		}

		// Sort
		return filtered.sort((a, b) => {
			let comparison = 0;
			switch (sortField) {
				case 'time':
					comparison =
						(Number(a.captureTime?.seconds) || 0) - (Number(b.captureTime?.seconds) || 0);
					break;
				case 'source':
					comparison = a.src.localeCompare(b.src);
					break;
				case 'destination':
					comparison = a.dst.localeCompare(b.dst);
					break;
				case 'type':
					comparison = getPacketType(a).localeCompare(getPacketType(b));
					break;
				case 'size':
					const sizeA = a.data.oneofKind === 'raw' ? a.data.raw.payload.length : 0;
					const sizeB = b.data.oneofKind === 'raw' ? b.data.raw.payload.length : 0;
					comparison = sizeA - sizeB;
					break;
			}
			return sortDirection === 'asc' ? comparison : -comparison;
		});
	}

	function toggleSort(field: SortField) {
		if (sortField === field) {
			sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
		} else {
			sortField = field;
			sortDirection = 'asc';
		}
		filteredAndSortedPackets = filterAndSortPackets(packetList);
	}

	function toggleProtocolFilter(protocol: string) {
		if (selectedProtocols.has(protocol)) {
			selectedProtocols.delete(protocol);
		} else {
			selectedProtocols.add(protocol);
		}
		selectedProtocols = selectedProtocols;
	}

	function clearFilters() {
		searchQuery = '';
		selectedProtocols.clear();
		selectedProtocols = selectedProtocols;
	}

	function formatTime(timestamp?: { seconds?: bigint }): string {
		if (!timestamp?.seconds) return '-';
		return new Date(Number(timestamp.seconds) * 1000).toLocaleTimeString();
	}

	function getPacketType(packet: Packet): string {
		switch (packet.data.oneofKind) {
			case 'ip': {
				const next = packet.data.ip.next;
				if (next.oneofKind === 'udp') {
					const udp = next as { oneofKind: 'udp'; udp: UDP };
					if (udp.udp.next.oneofKind === 'dns') return 'DNS';
					if (udp.udp.next.oneofKind === 'dhcp') return 'DHCP';
					if (udp.udp.next.oneofKind === 'dhcpv6') return 'DHCPv6';
					return 'UDP';
				}
				if (next.oneofKind === 'tcp') return 'TCP';
				if (next.oneofKind === 'icmp') return 'ICMP';
				return 'IP';
			}
			case 'ipv6': {
				const next = packet.data.ipv6.next;
				if (next.oneofKind === 'udp') {
					const udp = next as { oneofKind: 'udp'; udp: UDP };
					if (udp.udp.next.oneofKind === 'dns') return 'DNS';
					if (udp.udp.next.oneofKind === 'dhcp') return 'DHCP';
					if (udp.udp.next.oneofKind === 'dhcpv6') return 'DHCPv6';
					return 'UDP';
				}
				if (next.oneofKind === 'tcp') return 'TCP';
				if (next.oneofKind === 'icmpv6') return 'ICMPv6';
				return 'IPv6';
			}
			case 'arp':
				return 'ARP';
			case 'raw':
				return 'RAW';
			case 'dns':
				return 'DNS';
			case 'dhcp':
				return 'DHCP';
			case 'dhcpv6':
				return 'DHCPv6';
			default:
				return 'Unknown';
		}
	}

	function getPacketDetails(packet: Packet): string {
		switch (packet.data.oneofKind) {
			case 'raw':
				return `${packet.data.raw.payload.length} bytes`;
			case 'arp':
				return `${packet.data.arp.senderIpAddress} → ${packet.data.arp.targetIpAddress}`;
			case 'ip': {
				const ip = packet.data.ip;
				let details = `${ip.sourceAddress} → ${ip.destinationAddress}`;
				if (ip.next.oneofKind === 'tcp' && 'tcp' in ip.next) {
					details += ` | Port ${ip.next.tcp.sourcePort} → ${ip.next.tcp.destinationPort}`;
					details += `${ip.next.tcp.syn ? ' [SYN]' : ''}`;
					details += `${ip.next.tcp.ack ? ' [ACK]' : ''}`;
					details += `${ip.next.tcp.fin ? ' [FIN]' : ''}`;
				}
				return details;
			}
			case 'dhcp':
				return `${packet.data.dhcp.clientIpAddress} → ${packet.data.dhcp.serverIpAddress}`;
			case 'dns':
				return packet.data.dns.questions.map((q) => q.name).join(', ');
			default:
				return '-';
		}
	}

	async function startCapture() {
		try {
			const currentClient = get(client);
			const snifferId = get(activeSnifferId);
			const network = get(selectedNetwork);

			if (!currentClient || !snifferId || !network) {
				throw new Error('Missing required configuration for packet capture');
			}
			packets.set([]);
			packetList = [];
			filteredAndSortedPackets = [];

			isStreaming.set(true);

			const stream = currentClient.accessPointGetDecryptedStream({
				snifferUuid: snifferId,
				bssid: network.bssid,
				includePayload: true
			});

			for await (const packet of stream.responses) {
				if (!get(isStreaming)) break;
				packets.update((current) => {
					const updated = [...current, packet];
					if (updated.length > 1000) {
						return updated.slice(-1000);
					}
					return updated;
				});
			}
		} catch (e) {
			console.error('Packet capture error:', e);
			notifications.add('Failed to capture packets', 'error');
			isStreaming.set(false);
		}
	}

	function stopCapture() {
		if (streamController) {
			streamController.abort();
			streamController = null;
		}
		isStreaming.set(false);
	}

	onDestroy(() => {
		stopCapture();
	});

	async function startRecording(name: string) {
		try {
			const currentClient = get(client);
			const snifferId = get(activeSnifferId);
			const network = get(selectedNetwork);

			if (!currentClient || !snifferId) {
				throw new Error('Client or sniffer not initialized');
			}

			isLoading.set(true);

			let response;
			if (network) {
				response = await currentClient.accessPointCreateRecording({
					snifferUuid: snifferId,
					name: name,
					bssid: network.bssid,
					raw: false
				});
			} else {
				response = await currentClient.recordingCreate({
					snifferUuid: snifferId,
					name: name,
					raw: false
				});
			}

			console.log('Recording saved:', response.response);
			notifications.add(
				`Recording saved successfully. Captured ${response.response.packetCount} packets.`,
				'success'
			);
			showRecordingSaveModal = false;
		} catch (e) {
			console.error('Recording error:', e);
			notifications.add('Failed to save recording', 'error');
		} finally {
			isLoading.set(false);
		}
	}

	function togglePacketDetails(index: number) {
		expandedPacketId = expandedPacketId === index ? null : index;
	}
</script>

<div class="flex h-[800px] flex-col p-4">
	<div class="mb-4 flex items-center justify-between">
		<div class="flex-1">
			<div class="relative w-96">
				<div class="absolute left-2 top-2.5 text-gray-500">
					{@html IconSearch}
				</div>
				<Input type="text" placeholder="Search packets..." bind:value={searchQuery} class="pl-8" />
			</div>
		</div>
		<div class="flex items-center space-x-2">
			<div class="flex space-x-2">
				<!-- Record Button -->
				<Button
					on:click={() => (showRecordingSaveModal = true)}
					disabled={!$activeSnifferId || $isLoading}
					variant="outline"
					class="flex h-10 w-10 items-center justify-center p-0"
					title="Save Traffic Recording"
				>
					<svg
						xmlns="http://www.w3.org/2000/svg"
						class="h-5 w-5"
						viewBox="0 0 20 20"
						fill="currentColor"
					>
						<circle cx="10" cy="10" r="6" class="fill-current text-red-600" />
					</svg>
				</Button>

				<!-- Load Recording Button -->
				<Button
					on:click={() => (showRecordingLoader = true)}
					disabled={$isStreaming || $isLoading}
					variant="outline"
					class="flex h-10 w-10 items-center justify-center p-0"
					title="Load Recording"
				>
					<svg
						xmlns="http://www.w3.org/2000/svg"
						class="h-5 w-5"
						viewBox="0 0 20 20"
						fill="currentColor"
					>
						<path
							fill-rule="evenodd"
							d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zM6.293 6.707a1 1 0 010-1.414l3-3a1 1 0 011.414 0l3 3a1 1 0 01-1.414 1.414L11 5.414V13a1 1 0 11-2 0V5.414L7.707 6.707a1 1 0 01-1.414 0z"
							clip-rule="evenodd"
						/>
					</svg>
				</Button>

				<!-- Download Button -->
				<Button
					on:click={() => (window.location.href = '/download/')}
					variant="outline"
					class="flex h-10 w-10 items-center justify-center p-0"
					title="Go to Downloads"
				>
					<svg
						xmlns="http://www.w3.org/2000/svg"
						class="h-5 w-5"
						viewBox="0 0 20 20"
						fill="currentColor"
					>
						<path
							fill-rule="evenodd"
							d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zM6.293 6.707a1 1 0 010-1.414l3-3a1 1 0 011.414 0l3 3a1 1 0 01-1.414 1.414L11 5.414V13a1 1 0 11-2 0V5.414L7.707 6.707a1 1 0 01-1.414 0z"
							transform="rotate(180 10 10)"
							clip-rule="evenodd"
						/>
					</svg>
				</Button>
				<RecordingLoaderModal
					show={showRecordingLoader}
					onClose={() => (showRecordingLoader = false)}
				/>
				<RecordingSaveModal
					show={showRecordingSaveModal}
					onClose={() => (showRecordingSaveModal = false)}
					onSave={startRecording}
					network={$selectedNetwork}
				/>
			</div>

			<div class="mx-2 h-8 border-l border-gray-200"></div>

			<div class="space-x-2">
				<Button
					on:click={startCapture}
					disabled={$isStreaming || !$selectedNetwork}
					variant="default"
				>
					{$isStreaming ? 'Capturing...' : 'Start Capture'}
				</Button>
				<Button on:click={stopCapture} disabled={!$isStreaming} variant="destructive">
					Stop Capture
				</Button>
			</div>
		</div>
	</div>

	<div class="mb-4 flex flex-col space-y-4">
		<!-- Filter Controls -->
		<div class="flex items-center space-x-4">
			<div class="flex flex-wrap items-center space-x-2">
				<div class="text-gray-500">
					{@html IconFilter}
				</div>
				<div class="flex flex-wrap gap-2">
					{#each availableProtocols as protocol}
						<Button
							size="sm"
							variant={selectedProtocols.has(protocol) ? 'default' : 'outline'}
							on:click={() => toggleProtocolFilter(protocol)}
						>
							{protocol}
						</Button>
					{/each}
				</div>
				{#if selectedProtocols.size > 0 || searchQuery}
					<Button size="sm" variant="ghost" on:click={clearFilters}>Clear Filters</Button>
				{/if}
			</div>
		</div>

		<!-- Status Information -->
		<div class="flex justify-between text-sm text-gray-500">
			<div>
				{#if $selectedNetwork}
					Monitoring network: <span class="font-medium">{$selectedNetwork.ssid}</span>
					<span class="ml-2 text-xs">({$selectedNetwork.bssid})</span>
				{/if}
			</div>
			<div>
				Showing {filteredAndSortedPackets.length} of {packetList.length} packets
				{#if $isStreaming}
					<span class="ml-2 text-green-500">● Live</span>
				{/if}
			</div>
		</div>
	</div>
	{#if filteredAndSortedPackets.length === 0}
		{#if searchQuery || selectedProtocols.size > 0}
			<div class="flex h-96 items-center justify-center">
				<div class="max-w-md text-center">
					<h3 class="text-foreground text-lg font-medium">No matching packets</h3>
					<p class="text-muted-foreground mt-2">
						No packets match your current filters. Try adjusting your search criteria or clearing
						filters.
					</p>
				</div>
			</div>
		{:else}
			<div class="flex h-96 items-center justify-center">
				<div class="max-w-md text-center">
					<h3 class="mb-6 text-lg font-semibold">Getting Started</h3>
					<div class="space-y-6 text-gray-600">
						<div class="flex items-center space-x-4">
							<div
								class="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-full bg-blue-100"
							>
								<svg
									xmlns="http://www.w3.org/2000/svg"
									class="h-6 w-6 text-blue-600"
									viewBox="0 0 24 24"
									fill="none"
									stroke="currentColor"
								>
									<path
										stroke-linecap="round"
										stroke-linejoin="round"
										stroke-width="2"
										d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
									/>
								</svg>
							</div>
							<p class="text-left">1. Select and focus network to sniff on it</p>
						</div>

						<div class="flex items-center space-x-4">
							<div
								class="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-full bg-purple-100"
							>
								<svg
									xmlns="http://www.w3.org/2000/svg"
									class="h-6 w-6 text-purple-600"
									viewBox="0 0 24 24"
									fill="none"
									stroke="currentColor"
								>
									<path
										stroke-linecap="round"
										stroke-linejoin="round"
										stroke-width="2"
										d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
									/>
								</svg>
							</div>
							<p class="text-left">
								2. Wait for handshake packets from the client or deauthenticate them
							</p>
						</div>

						<div class="flex items-center space-x-4">
							<div
								class="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-full bg-green-100"
							>
								<svg
									xmlns="http://www.w3.org/2000/svg"
									class="h-6 w-6 text-green-600"
									viewBox="0 0 24 24"
									fill="none"
									stroke="currentColor"
								>
									<path
										stroke-linecap="round"
										stroke-linejoin="round"
										stroke-width="2"
										d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
									/>
								</svg>
							</div>
							<p class="text-left">
								3. Decrypt network using password or export password to hashcat
							</p>
						</div>

						<div class="flex items-center space-x-4">
							<div
								class="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-full bg-red-100"
							>
								<svg
									xmlns="http://www.w3.org/2000/svg"
									class="h-6 w-6 text-red-600"
									viewBox="0 0 24 24"
									fill="none"
									stroke="currentColor"
								>
									<path
										stroke-linecap="round"
										stroke-linejoin="round"
										stroke-width="2"
										d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"
									/>
								</svg>
							</div>
							<p class="text-left">4. Stream and record packets</p>
						</div>
					</div>
				</div>
			</div>
		{/if}
	{:else}
		<VirtualizedPacketViewer
			packets={filteredAndSortedPackets}
			{expandedPacketId}
			onPacketClick={togglePacketDetails}
			{getPacketType}
			{getPacketDetails}
			{formatTime}
		/>
	{/if}
</div>
