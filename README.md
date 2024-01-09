# SniffSniff

## Download

```
git clone https://github.com/TypicalAM/SniffSniff
cd SniffSniff/backend
git-crypt unlock ../../key # if you want to have access to our own pcap files
```

## Build

**NOTE - Full docker support coming soon!**

### Backend

#### Prerequisites

- `grpc`, installed locally (advised)
- `libtins`
- `libpcap`
- `cmake`
- `ninja` (optional)
- `boost`, specifically `boost::log`

##### Preparation

To generate the packets service definition:

```
protoc -I ../protos --grpc_out=src --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` ../protos/packets.proto
protoc -I ../protos --cpp_out=src ../protos/packets.proto
```

##### Run

To build & run with pin support:

```
cmake -DCMAKE_PREFIX_PATH=$MY_GRPC_INSTALL_DIR -DWITH_MAYHEM=ON -G Ninja -B build .
ninja -C build
./sniffsniff
```

Without pin support (development):

```
cmake -DCMAKE_PREFIX_PATH=$MY_GRPC_INSTALL_DIR -G Ninja -B build .
ninja -C build
./sniffsniff
```

### Frontend

#### Prerequisites

- `npm`
- `protoc-gen-js` - can be installed via npm
- `protoc-gen-grpc-web` - can be installed via npm

##### Preparation

To generate the packets service definition:

```
protoc -I=../protos --js_out=import_style=commonjs:src ../protos/packets.proto
protoc -I=../protos --grpc-web_out=import_style=commonjs,mode=grpcwebtext:src ../protos/packets.proto
```

##### Run

To build and run on `1234`

```
npm install
npx tsc && npx webpack && python3 -m http.server 1234
```
