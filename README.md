# Yarilo

Yarilo is an offensive security tool and packet sniffer designed for capturing and decrypting WPA2-PSK encrypted wireless network traffic. This project can analyze and interpret packets on WPA2-protected networks, aiding in network security assessments and understanding wireless communication protocols.

**Capabilities**:
- Detecting nearby networks
- Sniffing and decrypting packets in WPA2-PSK networks
- Exporting decrypted packets to a `pcap` format
- Loading decrypted recordings from a `pcap/pcapng` file
- Deauthenticating clients in a network (with caveats)
- Efficient channel hopping (work in progress)
- ARP poisoning (work in progress)
- Brute-forcing passwords (work in progress)
- Decrypting WEP packets (work in progress)

**The project consists of two components**:
- Sniffer - packet capturing backend written in C++
- Web Client - controlling the sniffer and viewing data (moving to `sveltekit` soon) 

## Release

Let's talk about running the release version of `Yarilo`, we strongly encourage running the sniffer through docker because of the issues that arise while compiling `grpc` by hand (it takes a lot of time on smaller devices).

### Sniffer

You can use `typicalam/yarilo:latest` as the base docker image. This project has two modes - file mode and interface mode. File mode runs the sniffer and analyzer on file recordings to decrypt existing data. Interface mode allows Yarlilo to take in a NIC (network interface card) and use that to sniff out network traffic captured by the card. You can also provide it a directory (shared volume) to be able to save the decrypted data. An example docker-compose file achieving this is below:

```yaml
version: '3.8'

services:
  yarilo:
    image: typicalam/yarilo:latest
    command: ./run.sh --port 69420 --iface=wlp5s0f3u2
    volumes:
      - /tmp/MY_SAVE_DIRECTORY:/opt/sniff
    network_mode: host # Note: This works only on linux
    cap_add:
      - NET_ADMIN
```

To run it just do:

```sh
docker compose -f docker-compose.srv.yml up -d
```

### Client

Let's say the sniffer is available at the local network address `10.0.0.1`. To run the frontend:

```sh
SERVER_ADDR=10.0.0.1 docker-compose -f docker-compose.prod.yml up
```

A simple web server should appear at: `http://localhost:1234/main.html`. Pressing the `Get available networks` button should return the scanned networks. If your sniffer isn't running in docker (see below) you should also run the `envoy` proxy like so: `docker-compose -f docker-compose.prod.yml up proxy`.

## Development

What about running this thing locally?

### Sniffer

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

## Extras - Pinhandler

Pin handler can be used to communicate between the host machine (with the LEDs and suchlike) and the container, it does so by using special `gprc` endpoints which stream the LED state. If you wish to see some action on your host machine you can run the following in the `pinhandler` directory:

```
python -m pip install grpcio grpcio-tools
python -m grpc_tools.protoc -I../protos --python_out=. --pyi_out=. --grpc_python_out=. ../protos/packets.proto
python3 handler.py localhost:9090
```
