FROM node:21-bookworm-slim

ARG SERVER_ADDR=localhost:8080

RUN apt-get -y update
RUN apt-get -y install git python3 protobuf-compiler

WORKDIR /opt
RUN git clone https://github.com/TypicalAM/Yarilo app
WORKDIR /opt/app/frontend
RUN npm install
RUN npm install -g protoc-gen-js protoc-gen-grpc-web
RUN protoc -I=../protos --js_out=import_style=commonjs:src ../protos/packets.proto
RUN protoc -I=../protos --grpc-web_out=import_style=commonjs,mode=grpcwebtext:src ../protos/packets.proto
RUN sed -i "s|http://localhost:8080|http://$SERVER_ADDR|g" src/client.ts

RUN npx tsc
RUN npx webpack
CMD ["python3", "-m", "http.server", "1234"]
