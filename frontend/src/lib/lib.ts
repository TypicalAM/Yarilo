import { SniffinsonClient } from './packets_grpc_web_pb';

const API_URL = 'http://localhost:8080';

const sniffClient = new SniffinsonClient(API_URL)

export async function getClient() {
	return sniffClient;
}
