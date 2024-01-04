# SniffSniff

## Build

### Requirements

- `cmake`
- `libtins`
- `ninja`
- `boost` (for logging)
- `grpc` (for backend communication)

### Download

```
git clone https://github.com/TypicalAM/SniffSniff
cd SniffSniff/backend
git-crypt unlock ../../key # if you want to have access to our own pcap files
```

### Build

## Backend

```
export MY_INSTALL_DIR=$HOME/.local # path to your LOCAL grpc installation
export PATH="$MY_INSTALL_DIR/bin:$PATH"

protoc -I ../protos --grpc_out=src --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` ../protos/packets.proto
protoc -I ../protos --cpp_out=src ../protos/packets.proto
cmake -DCMAKE_PREFIX_PATH=$MY_INSTALL_DIR -G Ninja -B build .
ninja -C build
./sniffsniff
```

## Frontend


### Setup

```
sudo npm install -g protoc-gen-js
sudo npm install -g protoc-gen-grpc-web
protoc -I=../protos --js_out=import_style=commonjs:src ../protos/packets.proto
protoc -I=../protos --grpc-web_out=import_style=commonjs,mode=grpcwebtext:src ../protos/packets.proto
docker compose up -d

npm install
npx tsc && npx webpack && python3 -m http.server 1234
npx webpack && python3 -m http.server 1234
```
