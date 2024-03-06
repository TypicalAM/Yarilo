import { writable } from "svelte/store";
import type { SniffinsonClient } from "./proto/packets.client";

export const client = writable<SniffinsonClient>(undefined);
