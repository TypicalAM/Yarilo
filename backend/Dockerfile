# syntax=docker/dockerfile:1

FROM phusion/baseimage:jammy-1.0.4

# We take the mayhem option as an argument
ARG MAYHEM_SUPPORT=OFF

# Copy the binaries and libs from the builder
COPY --from=typicalam/yarilo-build:latest /app/deps /app/deps

# Prepare runtime deps
RUN apt-get update \
	&& apt-get install -y --no-install-recommends git build-essential cmake ninja-build libpcap-dev libssl-dev libspdlog-dev libnl-3-dev libnl-nf-3-dev libnl-route-3-dev libnl-genl-3-dev \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/*

# Build yarilo
RUN git clone https://github.com/TypicalAM/Yarilo /app/src \
	&& cmake -DYARILO_WITH_MAYHEM=$MAYHEM_SUPPORT -B /app/src/backend/build -G Ninja /app/src/backend \
	&& ninja -C /app/src/backend/build && mv /app/src/backend/build/yarilo /yarilo

# Set up the run script
run echo $pwd && exit 1
COPY <<EOF ./run.sh
#!/bin/bash
/app/deps/bin/envoy -c /app/src/backend/envoy.yaml --log-path /app/envoy.log >/dev/null 2>&1 &
/yarilo \$*
EOF

# Set the script as executable
RUN chmod +x run.sh
