FROM ubuntu:24.04

# Prepare deps
RUN apt-get update -y
RUN apt-get install -y build-essential ninja-build wget git autoconf libtool pkg-config curl libpcap-dev libssl-dev libboost-log-dev

# Download a newer cmake than the ubuntu one (it's laughably old)  
RUN wget -q -O cmake-linux.sh https://github.com/Kitware/CMake/releases/download/v3.19.6/cmake-3.19.6-Linux-x86_64.sh
RUN mkdir /opt/cmake /opt/grpc
RUN sh cmake-linux.sh -- --skip-license --prefix=/opt/cmake
RUN rm cmake-linux.sh

# Download and install grpc
WORKDIR /opt
RUN git clone --recurse-submodules -b v1.60.0 --depth 1 --shallow-submodules https://github.com/grpc/grpc
WORKDIR /opt/grpc
RUN git submodule update
RUN mkdir /opt/grpc/cmake/build
WORKDIR /opt/grpc/cmake/build
RUN /opt/cmake/bin/cmake -DgRPC_INSTALL=ON -DgRPC_BUILD_TESTS=OFF ../..
RUN make -j 4
RUN make install

# Download and install libtins
WORKDIR /opt
RUN git clone https://github.com/mfontanini/libtins
RUN mkdir /opt/libtins/build
WORKDIR /opt/libtins/build
RUN /opt/cmake/bin/cmake .. -DLIBTINS_ENABLE_CXX11=1
RUN make -j 4
RUN make install

# Install sniffsniff
WORKDIR /opt
RUN git clone https://github.com/TypicalAM/SniffSniff
WORKDIR /opt/SniffSniff/backend
RUN /opt/cmake/bin/cmake -G Ninja -B build .
RUN ninja -C build