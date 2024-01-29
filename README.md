# SniffSniff

SniffSniff is an offensive security tool and packet sniffer designed for capturing and decrypting WPA2-PSK encrypted wireless network traffic. This peoject can analyze and interpret packets on WPA2-protected networks, aiding in network security assessments and understanding wireless communication protocols.

Capabilities:
- Detecting nearby networks
- Sniffing and decrypting packets in WPA2-PSK networks
- Exporting decrypted packets to a `pcap` format
- Loading decrypted recordings from `pcap`
- Deauthenticating clients in a network (with caveats)
- Efficient channel hopping (work in progress)
- ARP spoofing (work in progress)
- Brute-forcing WPA2 passwords (work in progress)
- Decrypting WEP packets (work in progress)

The project consists of three components:
- Sniffer - `grpc` backend written in C++
- Envoy proxy for `grpc-web` (web browsers don't support `grpc` natively)
- Simple web frontend (moving to `sveltekit` soon) 

## How to use?

### Client setup

#### Scenario 1 (basic):
- Sniffer is a device on a local network (with the address being let's say 10.0.0.1)
- Proxy & Frontend ran on the client's device

Run in the root directory:

```sh
SERVER_ADDR=10.0.0.1 docker-compose -f docker-compose.prod.yml up
```

*Note that network-mode = 'host' may not work on macos and windows*

A simple web server should appear at: `http://localhost:1234/main.html`. Pressing the `Get available networks` button should return the scanned networks.

#### Scenario 2 (less performant):
- Sniffer is a device on a local network
- Proxy is ran on the backend and is the only entrypoint to the sniffing device
- Frontend ran on the client's device

Run in the root directory:

```sh
SERVER_ADDR=10.0.0.1:8080 docker-compose -f docker-compose.prod.yml up frontend
```

A simple web server should appear at: `http://localhost:1234/main.html`. Pressing the `Get available networks` button should return the scanned networks.

### Server setup
- Sniffer is ran on our device
- Proxy can be ran on our device (look above for scenarios)
- Frontend ran on the client's device

Running the proxy (optional, only in docker mode): `docker-compose -f docker-compose.prod.yml up proxy`

#### Docker mode

You can use `typicalam/sniffsniff-mayhem-2:latest` as the base docker image. *TODO: Expand this section*

#### Compiled mode

Run in the backend directory (`$MY_GRPC_INSTALL_DIR` should be your `grpc` install dir):

Prepare definitions:

```sh
protoc -I ../protos --grpc_out=src --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` ../protos/packets.proto
protoc -I ../protos --cpp_out=src ../protos/packets.proto
```

Run with mayhem support:

```sh
cmake -DCMAKE_PREFIX_PATH=$MY_GRPC_INSTALL_DIR -DWITH_MAYHEM=ON -G Ninja -B build .
ninja -C build
./sniffsniff --help
```

Without mayhem support:

```sh
cmake -DCMAKE_PREFIX_PATH=$MY_GRPC_INSTALL_DIR -G Ninja -B build .
ninja -C build
./sniffsniff --help
```
