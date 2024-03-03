#!/usr/bin/env sh

protoc -I=../protos ../protos/packets.proto --js_out=import_style=commonjs:src/lib/proto/
protoc -I=../protos ../protos/packets.proto --grpc-web_out=import_style=typescript,mode=grpcwebtext:src/lib/proto/
