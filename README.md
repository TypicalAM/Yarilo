# Yarilo

Yarilo is an offensive security tool and packet sniffer designed for capturing and decrypting WPA2-PSK encrypted wireless network traffic. This project can analyze and interpret packets on WPA2-protected networks, aiding in network security assessments and understanding wireless communication protocols.

Capabilities:
- Detecting nearby networks
- Sniffing and decrypting packets in WPA2-PSK networks
- Exporting decrypted packets to a `pcap` format
- Loading decrypted recordings from `pcap`
- Deauthenticating clients in a network (with caveats)
- Efficient channel hopping (work in progress)
- ARP poisoning (work in progress)
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

You can use `typicalam/yarilo:v0.1` as the base docker image. To function properly, it needs three things:

- (Ideally) NIC (network interface card) passed through to the docker container
- (Optionally) A shared volume between the host and the guest to retrieve `pcap` recordings of the decrypted data

An example docker-compose file achieving this is below:

```
version: '3.8'

services:
  yarilo:
    image: typicalam/yarilo:v0.1-mayhem
    command: >
      sh -c "/app/deps/bin/envoy -c /app/src/backend/envoy.yaml &
             /yarilo --fromfile=no --iface=wlp5s0f3u2"
    volumes:
      - /tmp/MY_SAVE_DIRECTORY:/opt/sniff
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
./yarilo --help
```

Without mayhem support:

```sh
cmake -DCMAKE_PREFIX_PATH=$MY_GRPC_INSTALL_DIR -G Ninja -B build .
ninja -C build
./yarilo --help
```

#### Pinhandler

Pin handler is used to communicate between the host machine (with the LEDs and suchlike) and the container, it does so by using special `gprc` endpoints which stream the LED state. If you wish to see some action on your host machine you can run the following in the `pinhandler` directory:

```
python -m pip install grpcio grpcio-tools
python -m grpc_tools.protoc -I../protos --python_out=. --pyi_out=. --grpc_python_out=. ../protos/packets.proto
python3 handler.py localhost:9090
```
