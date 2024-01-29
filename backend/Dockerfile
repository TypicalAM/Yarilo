FROM ubuntu:24.04

# We take the target platform and build it conditionally
ARG TARGETPLATFORM

# Prepare deps
RUN apt-get update -y
RUN apt-get install -y git sudo build-essential ninja-build wget autoconf libtool pkg-config curl libpcap-dev libssl-dev libboost-log-dev iproute2 net-tools wireless-tools iw

# Download a newer cmake than the ubuntu one (it's laughably old)  
RUN if [ "$TARGETPLATFORM" = "linux/arm64" ] ; then \
	wget -q -O cmake-linux.sh https://github.com/Kitware/CMake/releases/download/v3.19.6/cmake-3.19.6-Linux-aarch64.sh; \
	else \
	wget -q -O cmake-linux.sh https://github.com/Kitware/CMake/releases/download/v3.19.6/cmake-3.19.6-Linux-x86_64.sh; \
	fi;
RUN mkdir /opt/cmake
RUN sh cmake-linux.sh -- --skip-license --prefix=/opt/cmake
RUN rm cmake-linux.sh

# Download and install grpc
WORKDIR /opt
RUN mkdir /opt/grpc
RUN git clone --recurse-submodules -b v1.60.0 --depth 1 --shallow-submodules https://github.com/grpc/grpc
WORKDIR /opt/grpc
RUN git submodule update
RUN mkdir /opt/grpc/cmake/build
WORKDIR /opt/grpc/cmake/build
RUN /opt/cmake/bin/cmake -DgRPC_INSTALL=ON -DgRPC_BUILD_TESTS=OFF ../..
RUN make -j 4
RUN make install
RUN rm -rf /opt/grpc

# Download and install libtins
WORKDIR /opt
RUN git clone https://github.com/mfontanini/libtins
RUN mkdir /opt/libtins/build
WORKDIR /opt/libtins/build
RUN /opt/cmake/bin/cmake .. -DLIBTINS_ENABLE_CXX11=1 -DLIBTINS_ENABLE_ACK_TRACKER=0
RUN make -j 4
RUN make install
RUN rm -rf /opt/libtins

# Build sniffsniff
WORKDIR /opt
RUN git clone https://github.com/TypicalAM/SniffSniff
WORKDIR /opt/SniffSniff/backend
RUN if [ "$TARGETPLATFORM" = "linux/arm64" ] ; then \
	/opt/cmake/bin/cmake -DWITH_MAYHEM=ON -G Ninja -B build .; \
	else \
	/opt/cmake/bin/cmake -DWITH_MAYHEM=OFF -G Ninja -B build .; \
	fi;
RUN ninja -C build

# Download the envoy proxy
WORKDIR /opt
RUN mkdir /opt/envoy
RUN if [ "$TARGETPLATFORM" = "linux/arm64" ] ; then \
 	wget -q -O /opt/envoy/envoy https://github.com/envoyproxy/envoy/releases/download/v1.29.0/envoy-1.29.0-linux-aarch_64; \
	else \
 	wget -q -O /opt/envoy/envoy https://github.com/envoyproxy/envoy/releases/download/v1.29.0/envoy-1.29.0-linux-x86_64; \
	fi;
RUN chmod +x /opt/envoy/envoy
