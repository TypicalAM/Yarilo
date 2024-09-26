<script lang="ts">
    import '../app.pcss';
    import { onMount } from 'svelte';
    import { SnifferClient } from '$proto/packets.client';
    import { client, streaming, toggleStreaming } from '$stores';
    import { GRPC_URL } from '$env';
    import { GrpcWebFetchTransport } from '@protobuf-ts/grpcweb-transport';
    import { goto } from '$app/navigation';

    let isStreaming: boolean;

    streaming.subscribe(value => {
        isStreaming = value;
    });

    onMount(() => {
        console.log('Creating client');
        const snifferService = new SnifferClient(
            new GrpcWebFetchTransport({
                baseUrl: GRPC_URL
            })
        );
        console.log('Client created');
        client.set(snifferService);
    });
</script>

<style>
    :global(html, body) {
        height: 100%;
        margin: 0;
        padding: 0;
        font-family: Arial, sans-serif;
        background-color: #2F2733;
        color: white;
    }

    #app {
        display: flex;
        flex-direction: column;
        min-height: 100vh;
    }

    header {
        background-color: #1f1f1f;
        padding: 10px 20px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .logo {
        height: 50px;
        width: auto;
    }

    nav {
        display: flex;
        gap: 20px;
        align-items: center;
    }

    nav a {
        color: white;
        text-decoration: none;
    }

    main {
        flex: 1;
        padding: 20px;
    }

    footer {
        background-color: #1f1f1f;
        padding: 10px 20px;
        text-align: center;
    }

    .stream-button {
        background-color: #bb3535;
        color: white;
        border: none;
        padding: 10px 20px;
        cursor: pointer;
        transition: background-color 0.3s;
    }
    .stream-button:hover {
        background-color: #d04545;
    }
    .stream-button.active {
        background-color: #45bb45;
    }
    .stream-button.active:hover {
        background-color: #55d055;
    }
</style>

<div id="app">
    <header>
        <img src="/src/images/yarilo.png" alt="YARILO Logo" class="logo">
        <nav>
            <a href="/" on:click|preventDefault={() => goto('/')}>Główna</a>
            <a href="/statystyki" on:click|preventDefault={() => goto('/statystyki')}>Statystyki</a>
            <button class="stream-button" class:active={isStreaming} on:click={toggleStreaming}>
                STREAM {isStreaming ? 'OFF' : 'ON'}
            </button>
        </nav>
    </header>

    <main>
        <slot></slot>
    </main>

    <footer>
        <p>Autorzy: Adam Piaseczny, Aleksander Kwaśnioch, Igor Szczepaniak, Kuba Woźniak</p>
    </footer>
</div>