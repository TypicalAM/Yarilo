# syntax=docker/dockerfile:1

FROM phusion/baseimage:jammy-1.0.1

# We take the target platform and build it conditionally
ARG TARGETPLATFORM

# Copy the binaries and libs from the builder
COPY --from=typicalam/sniffsniff-build:v0.1 /app/deps /app/deps

# Prepare runtime deps
RUN apt-get update \
	&& apt-get install -y --no-install-recommends build-essential=12.9ubuntu3 ninja-build=1.10.1-1 libpcap-dev=1.10.1-4build1 libssl-dev=3.0.2-0ubuntu1.13 git=1:2.34.1-1ubuntu1.10 iw=5.16-1build1 \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/*

# Build sniffsniff
RUN git clone https://github.com/TypicalAM/SniffSniff /app/src
RUN if [ "$TARGETPLATFORM" = "linux/arm64" ] ; then \
	/app/deps/bin/cmake -DWITH_MAYHEM=ON -B /app/src/backend/build -G Ninja /app/src/backend; \
	else \
	/app/deps/bin/cmake -DWITH_MAYHEM=OFF -B /app/src/backend/build -G Ninja /app/src/backend; \
	fi
RUN ninja -C build
