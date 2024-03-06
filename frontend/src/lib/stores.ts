import { writable } from "svelte/store";
import type { GreeterClient } from "./proto/GreeterServiceClientPb";

export const grpcClient = writable<GreeterClient>(undefined);
