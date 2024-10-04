import { writable } from "svelte/store";
import type { SnifferClient } from "./proto/service.client";

export const client = writable<SnifferClient>(undefined);

export const ensureConnected = () => {
    const timeout = 3000;
    let start = Date.now()

    const waitForConnect = (resolve: () => void, reject: (reason?: any) => void) => {
        if (client !== undefined)
            resolve();
        else if (timeout && (Date.now() - start) >= timeout)
            reject(new Error("timeout"));
        else
            setTimeout(waitForConnect.bind(this, resolve, reject), 30);
    }

    return new Promise<void>(waitForConnect)
}
