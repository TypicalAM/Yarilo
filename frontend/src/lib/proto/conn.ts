import { writable } from "svelte/store";
import { SniffinsonClient } from "$lib/proto/PacketsServiceClientPb";

const API_URL = 'http://localhost:8080';

export const api = writable<SniffinsonClient | null>(null);

export function connectToSniffer() {
	console.log(`Connecting to sniffer instance at ${API_URL}`)
	const sniffClient = new SniffinsonClient(API_URL)
	api.set(sniffClient);
}
