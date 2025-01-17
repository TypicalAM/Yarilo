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

You can use `typicalam/yarilo:latest` as the base docker image. This project has two modes - file mode and interface mode. File mode runs the sniffer and analyzer on file recordings to decrypt existing data. Interface mode allows Yarlilo to take in a NIC (network interface card) and use that to sniff out network traffic captured by the card. You can also provide it a directory (shared volume) to be able to save the decrypted data. An example deployment **docker compose** file achieving is available at [docker-compose.yml](https://github.com/TypicalAM/Yarilo/blob/main/docker-compose.yml). To run it execute the following command in the repo root:

```sh
docker compose up -d
```

or if you on a host that does not support host networking (MacOS, Windows) you can run:

```sh
docker network create yarilo-net
docker run --rm -d --net yarilo-net -p 8080:8080 -e "YARILO_ADDRESS=yarilo" typicalam/yarilo-envoy:latest
docker run --rm -it --name yarilo --net yarilo-net -v /tmp/saves:/app/saves -v ./pcap:/tmp/pcap -p 9090:9090 typicalam/yarilo:latest --oid_file=/app/data/oid.txt --save_path=/app/saves --db_file=/app/saves/yarilo_database.db --sniff_file=/tmp/pcap/wireshark_sample.pcap
```

## Development

What about running this thing locally?

### Sniffer

Run in the backend directory (`$MY_GRPC_INSTALL_DIR` should be your `grpc` install dir):

Prepare definitions:

```sh
protoc -I ../protos --cpp_out=src/proto --grpc_out=src/proto --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` ../protos/service.proto
```

Compile and run:

```sh
cmake -DCMAKE_PREFIX_PATH=$MY_GRPC_INSTALL_DIR -G Ninja -B build .
ninja -C build
./build/yarilo --help
```

C++ reference documentation is built alongside the project if `-DYARILO_BUILD_DOCS=ON` is specified (requires `doxygen`). Open the `build/doc_doxygen/html/index.html` file in a browser to view. Optionally, for protobuf definitons to also be included in the docs, run the following before building (requires `go`):

```sh
go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@latest
protoc -I../protos --doc_opt=markdown,proto.md --doc_out=docs ../protos/service.proto
```

### Client

To run the client, enter the `frontend` directory and run:

```sh
npm install
npm run dev
```

If your sniffer isn't running in `docker` you should also run [envoy](https://www.envoyproxy.io/) like so: `envoy -c envoy/envoy.yaml`.

### License

Copyright (C) 2025 Adam Piaseczny, Aleksander Kwiaśnioch, Jakub Wolniak, Igor Szczepaniak

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
