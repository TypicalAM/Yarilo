import { writable, get } from "svelte/store";
import type { SnifferClient } from "./proto/packets.client";

export const client = writable<SnifferClient | undefined>(undefined);
export const streaming = writable<boolean>(false);

export const ensureConnected = () => {
    const timeout = 3000;
    let start = Date.now()

    const waitForConnect = (resolve: () => void, reject: (reason?: any) => void) => {
        if (get(client) !== undefined)
            resolve();
        else if (timeout && (Date.now() - start) >= timeout)
            reject(new Error("timeout"));
        else
            setTimeout(waitForConnect.bind(this, resolve, reject), 30);
    }

    return new Promise<void>(waitForConnect)
}

export const toggleStreaming = () => {
    streaming.update(value => !value);
}