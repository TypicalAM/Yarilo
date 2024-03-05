import { writable } from "svelte/store";
import { SniffinsonClient } from "$lib/proto/packets.client";
import { GrpcWebFetchTransport } from "@protobuf-ts/grpcweb-transport";

const API_URL = 'http://localhost:8080';

export const api = writable<SniffinsonClient | null>(null);

export function connectToSniffer() {
	console.log(`Connecting to sniffer instance at ${API_URL}`)
	const sniffClient = new SniffinsonClient(new GrpcWebFetchTransport({ baseUrl: API_URL }))
	console.log(`Connected to sniffer`)
	api.set(sniffClient);
}
