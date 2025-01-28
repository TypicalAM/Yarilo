declare module '@sveltejs/svelte-virtual-list' {
    import { SvelteComponentTyped } from 'svelte';

    interface VirtualListProps<T> {
        items: T[];
        height?: string | number;
        itemHeight?: number;
    }

    export default class VirtualList<T> extends SvelteComponentTyped<VirtualListProps<T>> { }
}