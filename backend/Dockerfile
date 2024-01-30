# syntax=docker/dockerfile:1

FROM phusion/baseimage:focal-1.2.0

# We take the mayhem option as an argument
ARG FIFO_SUPPORT=OFF

# Copy the binaries and libs from the builder
COPY --from=typicalam/yarilo-build:v0.1 /app/deps /app/deps

# Prepare runtime deps
RUN apt-get update \
	&& apt-get install -y --no-install-recommends build-essential ninja-build libpcap-dev libssl-dev git iw iproute2 wireless-tools \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/*

# Build yarilo
RUN git clone https://github.com/TypicalAM/Yarilo /app/src \
	&& /app/deps/bin/cmake -DWITH_MAYHEM=$FIFO_SUPPORT -B /app/src/backend/build -G Ninja /app/src/backend \
	&& ninja -C /app/src/backend/build && mv /app/src/backend/build/yarilo /yarilo
