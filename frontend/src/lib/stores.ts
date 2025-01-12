import { writable, derived, get } from 'svelte/store';
import type { SnifferClient } from './proto/service.client';
import type { 
    Packet, 
    AccessPointInfo, 
    BasicNetworkInfo, 
    NetworkInterfaceListResponse,
    SnifferInfo 
} from './proto/service';

// Core client store
export const client = writable<SnifferClient | undefined>(undefined);

// Active sniffer state
export const activeSnifferId = writable<string | null>(null);
export const selectedNetwork = writable<BasicNetworkInfo | null>(null);
export const availableNetworks = writable<BasicNetworkInfo[]>([]);
export const networkInterfaces = writable<string[]>([]);
export const currentSniffer = writable<SnifferInfo | null>(null);

// Connection state tracking
export const connectionStatus = writable<'disconnected' | 'connecting' | 'connected'>('disconnected');

// Packet capture & streaming state
export const isStreaming = writable<boolean>(false);
export const packets = writable<Packet[]>([]);
export const maxPackets = writable<number>(1000);

// UI state
export const isLoading = writable<boolean>(false);
export const error = writable<string | null>(null);

// Enhanced connection management
let connectPromise: Promise<void> | null = null;

export const ensureConnected = async () => {
    if (get(connectionStatus) === 'connected') return;
    if (connectPromise) return connectPromise;

    connectionStatus.set('connecting');
    
    connectPromise = new Promise<void>((resolve, reject) => {
        const start = Date.now();
        const timeout = 5000;

        const checkConnection = () => {
            const currentClient = get(client);
            
            if (currentClient) {
                connectionStatus.set('connected');
                resolve();
                return;
            }

            if (Date.now() - start >= timeout) {
                connectionStatus.set('disconnected');
                reject(new Error('Connection timeout after 5s'));
                return;
            }

            setTimeout(checkConnection, 100);
        };

        checkConnection();
    });

    try {
        await connectPromise;
    } finally {
        connectPromise = null;
    }

    return connectPromise;
};

// Enhanced sniffer initialization
export const initializeSniffer = async () => {
    const currentClient = get(client);
    if (!currentClient) {
        throw new Error('Client not initialized');
    }

    try {
        isLoading.set(true);

        // Check existing sniffers first
        const snifferListResponse = await currentClient.snifferList({});
        if (snifferListResponse.response.sniffers.length > 0) {
            const existingSniffer = snifferListResponse.response.sniffers[0];
            activeSnifferId.set(existingSniffer.uuid);
            currentSniffer.set(existingSniffer);
            return existingSniffer.uuid;
        }

        // Get available interfaces
        const interfacesResponse = await currentClient.networkInterfaceList({});
        if (interfacesResponse.response.ifaces.length === 0) {
            throw new Error('No network interfaces available');
        }

        networkInterfaces.set(interfacesResponse.response.ifaces);

        // Create new sniffer
        const createResponse = await currentClient.snifferCreate({
            isFileBased: false,
            netIfaceName: interfacesResponse.response.ifaces[0],
            recordingUuid: ""
        });

        const newSnifferId = createResponse.response.snifferUuid;
        activeSnifferId.set(newSnifferId);
        
        return newSnifferId;

    } catch (e) {
        error.set(e instanceof Error ? e.message : 'Failed to initialize sniffer');
        throw e;
    } finally {
        isLoading.set(false);
    }
};

// Rest of your existing store functions
export const addPacket = (newPacket: Packet) => {
    packets.update(currentPackets => {
        const updatedPackets = [...currentPackets, newPacket];
        const max = get(maxPackets);
        
        if (updatedPackets.length > max) {
            return updatedPackets.slice(-max);
        }
        return updatedPackets;
    });
};

export const clearPackets = () => {
    packets.set([]);
};

export const startStreaming = async () => {
    const currentClient = get(client);
    const currentSnifferId = get(activeSnifferId);
    const currentNetwork = get(selectedNetwork);
    
    if (!currentClient || !currentSnifferId || !currentNetwork) {
        throw new Error('Missing required streaming configuration');
    }

    try {
        isLoading.set(true);
        const stream = currentClient.accessPointGetDecryptedStream({
            snifferUuid: currentSnifferId,
            bssid: currentNetwork.bssid,
            includePayload: true
        });

        isStreaming.set(true);
        
        for await (const packet of stream.responses) {
            if (!get(isStreaming)) break;
            addPacket(packet);
        }
    } catch (e) {
        error.set(e instanceof Error ? e.message : 'Unknown error during streaming');
        throw e;
    } finally {
        isLoading.set(false);
        isStreaming.set(false);
    }
};

export const stopStreaming = () => {
    isStreaming.set(false);
};

export const setSelectedNetwork = async (network: BasicNetworkInfo) => {
    const currentClient = get(client);
    const currentSnifferId = get(activeSnifferId);

    if (!currentClient || !currentSnifferId) {
        throw new Error('Client or sniffer ID not available');
    }

    try {
        isLoading.set(true);
        const response = await currentClient.accessPointGet({
            snifferUuid: currentSnifferId,
            bssid: network.bssid
        });

        selectedNetwork.set(network);
        clearPackets();
    } catch (e) {
        error.set(e instanceof Error ? e.message : 'Unknown error selecting network');
        throw e;
    } finally {
        isLoading.set(false);
    }
};

export const setError = (message: string, timeout = 5000) => {
    error.set(message);
    if (timeout > 0) {
        setTimeout(() => error.set(null), timeout);
    }
};

export const filteredPackets = derived(
    [packets],
    ([$packets]) => $packets
);
