# syntax=docker/dockerfile:1

FROM phusion/baseimage:jammy-1.0.4

# We take the battery option as an argument
ARG BATTERY_SUPPORT=OFF

# Copy the binaries and libs from the builder
COPY --from=typicalam/yarilo-build:latest /app/deps /app/deps

# Prepare deps
RUN apt-get update \
	&& apt-get install -y --no-install-recommends git build-essential cmake ninja-build libpcap-dev libssl-dev libspdlog-dev libnl-3-dev libnl-nf-3-dev libnl-route-3-dev libnl-genl-3-dev golang-go doxygen \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/* \
	&& GOPATH=/app/deps go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@v1.5.1

# Build yarilo
RUN git clone https://github.com/TypicalAM/Yarilo /app/src \
	&& /app/deps/bin/protoc -I /app/src/protos --doc_opt=markdown,proto.md --doc_out=/app/src/backend/docs --plugin=protoc-gen-doc=/app/deps/bin/protoc-gen-doc /app/src/protos/service.proto \
	&& cmake -DCMAKE_PREFIX_PATH=/app/deps -DYARILO_BUILD_DOCS=ON -DYARILO_BATTERY_SUPPORT=$BATTERY_SUPPORT -B /app/src/backend/build -G Ninja /app/src/backend \
	&& ninja -C /app/src/backend/build && mv /app/src/backend/build/yarilo /yarilo

# Set up the run script
COPY <<EOF ./run.sh
#!/bin/bash
/app/deps/bin/envoy -c /app/src/backend/envoy.yaml --log-path /app/envoy.log >/dev/null 2>&1 &
/yarilo \$*
EOF

# Set the script as executable
RUN chmod +x run.sh
