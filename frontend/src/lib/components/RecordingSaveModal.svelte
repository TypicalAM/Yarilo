<script lang="ts">
	import { Button } from './ui/button';
	import { Input } from './ui/input';
	import type { BasicNetworkInfo } from '../proto/service';

	export let show = false;
	export let onClose = () => {};
	export let onSave = (name: string) => {};
	export let network: BasicNetworkInfo | null = null;

	let recordingName = '';

	$: if (show && network && !recordingName) {
		// Format: name_UUID_DATA.pcapng
		const date = new Date().toISOString().slice(0, 10).replace(/-/g, '');
		const time = new Date().toTimeString().slice(0, 5).replace(':', '');
		recordingName = `${network.ssid}_${date}_${time}`;
	}

	function handleSave() {
		if (recordingName.trim()) {
			onSave(recordingName.trim());
			recordingName = '';
		}
	}
</script>

<div
	class="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto overflow-x-hidden"
	role="dialog"
	aria-modal="true"
	class:hidden={!show}
>
	<!-- Faded background -->
	<div class="fixed inset-0 bg-black/50" on:click={onClose}></div>

	<!-- Modal contener -->
	<div class="relative z-50 m-4 w-full max-w-md rounded-lg bg-white">
		<!-- Header -->
		<div class="flex items-center justify-between border-b p-4">
			<h2 class="text-xl font-semibold">Save Network Traffic</h2>
			<button class="text-gray-500 hover:text-gray-700" on:click={onClose}>
				<svg
					xmlns="http://www.w3.org/2000/svg"
					class="h-6 w-6"
					fill="none"
					viewBox="0 0 24 24"
					stroke="currentColor"
				>
					<path
						stroke-linecap="round"
						stroke-linejoin="round"
						stroke-width="2"
						d="M6 18L18 6M6 6l12 12"
					/>
				</svg>
			</button>
		</div>

		<!-- Modal content -->
		<div class="space-y-4 p-6">
			<div>
				<label for="recording-name" class="mb-1 block text-sm font-medium text-gray-700">
					Recording Name
				</label>
				<Input
					id="recording-name"
					type="text"
					bind:value={recordingName}
					placeholder="Enter recording name"
					class="bg-white"
				/>
				{#if network}
					<p class="mt-1 text-sm text-gray-500">
						Will save traffic from network: {network.ssid}
					</p>
				{:else}
					<p class="mt-1 text-sm text-gray-500">Will save all traffic from current sniffer</p>
				{/if}
			</div>

			<div class="flex justify-end space-x-2">
				<Button variant="outline" on:click={onClose}>Cancel</Button>
				<Button variant="default" on:click={handleSave} disabled={!recordingName.trim()}>
					Save Traffic
				</Button>
			</div>
		</div>
	</div>
</div>
