#!/bin/bash

protoc -I ../protos --grpc_out=src --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` ../protos/packets.proto
protoc -I ../protos --cpp_out=src ../protos/packets.proto
/opt/cmake/bin/cmake -G Ninja -B build .
ninja -C build
./build/sniffsniff --fromfile --filename=pcap/wpa_induction.pcap
