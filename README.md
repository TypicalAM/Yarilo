# Yarilo

Yarilo is an offensive security tool and packet sniffer designed for capturing and decrypting encrypted wireless network traffic. This project can analyze and interpret packets on WPA2-protected networks with support for more coming soon. It can aid in network security assessments and understanding of wireless communication protocols.

**Capabilities**:
- Capturing and decrypting data from nearby networks
- Transferring data to/from `pcap`
- Replay attacks (deauth)
- Efficient channel hopping
- Brute-forcing passwords (work in progress)

**The project consists of two components**:
- Sniffer - packet capturing backend written in C++
- Web Client - controlling the sniffer and viewing data (moving to `sveltekit` soon) 

## Release

Let's talk about running the release version of `Yarilo`, we strongly encourage running the sniffer through docker because of the issues that arise while compiling `grpc` by hand (it takes a lot of time on smaller devices).

### Sniffer

You can use `typicalam/yarilo:latest` as the base docker image. This project has two modes - file mode and interface mode. File mode runs the sniffer and analyzer on file recordings to decrypt existing data. Interface mode allows Yarlilo to take in a NIC (network interface card) and use that to sniff out network traffic captured by the card. You can also provide it a directory (shared volume) to be able to save the decrypted data. An example deployment **docker compose** file achieving is available at [docker-compose.srv.yml](https://github.com/TypicalAM/Yarilo/blob/main/docker-compose.srv.yml). To run it execute the following command in the repo root:

```sh
docker compose -f docker-compose.srv.yml up -d
```

## Development

What about running this thing locally?

### Sniffer

Run in the backend directory (`$MY_GRPC_INSTALL_DIR` should be your `grpc` install dir):

Prepare definitions:

```sh
protoc -I ../protos --cpp_out=src --grpc_out=src --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` ../protos/packets.proto
```

Run with mayhem support:

```sh
cmake -DCMAKE_PREFIX_PATH=$MY_GRPC_INSTALL_DIR -DYARILO_WITH_MAYHEM=ON -G Ninja -B build .
ninja -C build
./build/yarilo --help
```

Without mayhem support:

```sh
cmake -DCMAKE_PREFIX_PATH=$MY_GRPC_INSTALL_DIR -G Ninja -B build .
ninja -C build
./build/yarilo --help
```

C++ reference documentation is built alongside the project if `-DYARILO_BUILD_DOCS=ON` is specified (requires `doxygen`). Open the `build/doc_doxygen/html/index.html` file in a browser to view. Optionally, for protobuf definitons to also be included in the docs, run the following before building (requires `go`):

```sh
go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@latest
protoc -I../protos --doc_opt=markdown,proto.md --doc_out=docs ../protos/packets.proto
```

### Client

To run the client, enter the `frontend` directory and run:

```sh
npm install
npm run proto:gen
npm run dev
```

If your sniffer isn't running in `docker` you should also run [envoy](https://www.envoyproxy.io/) like so: `envoy -c backend/envoy.yaml`.

## Extras - Pinhandler

Pin handler can be used to communicate between the host machine (with the LEDs and suchlike) and the container, it does so by using special `gprc` endpoints which stream the LED state. If you wish to see some action on your host machine you can run the following in the `pinhandler` directory:

```
python3 -m pip install grpcio grpcio-tools
python3 -m grpc_tools.protoc -I../protos --python_out=. --pyi_out=. --grpc_python_out=. ../protos/packets.proto
python3 handler.py localhost:9090
```
