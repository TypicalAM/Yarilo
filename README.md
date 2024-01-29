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
- Sniffer is a device on a local network (with the address being let's say 10.0.0.1)

Run in the root directory:

```sh
SERVER_ADDR=10.0.0.1 docker-compose -f docker-compose.prod.yml up
```

A simple web server should appear at: `http://localhost:1234/main.html`. Pressing the `Get available networks` button should return the scanned networks.

### Server setup
- Sniffer is ran on our device
- Proxy can be ran on our device (look above for scenarios)
- Frontend ran on the client's device

Running the proxy (optional, only in docker mode): `docker-compose -f docker-compose.prod.yml up proxy`

#### Docker mode

You can use `typicalam/sniffsniff-mayhem:latest` as the base docker image. To function properly, it needs three things:

- (Ideally) NIC (network interface card) passed through to the docker container
- Two fifos shared with the host
  - LED fifo (for the sniffer to tell the led's to light up)
  - Topgun fifo (for the host to tell the sniffer to start deauthing everyone)
  - those are passed thorught the `--led_fifo_filename=MY_LEDS_PATH` and `--topgun_fifo_filename=MY_TOPGUN_PATH` respectively
- (Optionally) A shared volume between the host and the guest to retrieve `pcap` recordings of the decrypted data

An example docker-compose file achieving this is below:

```
version: '3.8'

services:
  sniffsniff-server:
    build:
      context: ./
      dockerfile: ./backend/Dockerfile # Normally just use the typicalam/sniffsniff-mayhem image
      args:
        FIFO_SUPPORT: ON # Fifo support is turned off by defaut
    command: [
      "/app/src/backend/build/sniffsniff",
      "--fromfile=no",
      "--iface=wlp5s0f3u2",
      "--led_fifo_filename=/opt/fifos/led",
      "--topgun_fifo_filename=/opt/fifos/topgun"
    ]
    volumes:
      - /tmp/MY_SAVE_DIRECTORY:/opt/sniff
      - /tmp/MY_FIFO_DIRECTORY:/opt/fifos
    network_mode: host # Note: This works only on linux
    cap_add:
      - NET_ADMIN
```

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
