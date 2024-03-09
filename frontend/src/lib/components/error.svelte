<script lang="ts">
	export let message: string;

	import { ExclamationTriangle } from 'radix-icons-svelte';
	import * as Alert from '$lib/components/ui/alert';
</script>

<Alert.Root variant="destructive" class="absolute bottom-0 right-0 m-4 w-1/3">
	<ExclamationTriangle class="h-4 w-4" />
	<Alert.Title>This is an error!</Alert.Title>
	<Alert.Description>{message}</Alert.Description>
</Alert.Root>
