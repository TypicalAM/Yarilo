# syntax=docker/dockerfile:1

# Image to capture store closure
FROM nixos/nix:2.23.0 AS builder

# We take the battery option as an argument
ARG BATTERY_SUPPORT=OFF

# Copy source
COPY . /tmp/build
WORKDIR /tmp/build

# Build image
RUN if [ "$BATTERY_SUPPORT" = "ON" ] ; then \
	nix --extra-experimental-features "nix-command flakes" --option filter-syscalls false build .#YariloBattery; \
	else \
	nix --extra-experimental-features "nix-command flakes" --option filter-syscalls false build .; \
	fi;


# Copy the Nix store closure into a directory.
# entire set of Nix store values that we need for our build.
RUN mkdir /tmp/nix-store-closure
RUN cp -R "$(nix-store -qR result/)" /tmp/nix-store-closure

FROM scratch

WORKDIR /app

# Copy /nix/store
COPY --from=builder /tmp/nix-store-closure /nix/store
COPY --from=builder /build/result /app

EXPOSE 9090
ENTRYPOINT ["/app/bin/yarilo"]
