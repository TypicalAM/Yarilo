# syntax=docker/dockerfile:1

FROM nixos/nix:2.23.0 AS base

# Image to capture store closure
FROM base AS builder

# We take the battery option as an argument
ARG BATTERY_SUPPORT=OFF

# Capture deps into /nix/store, even when building dev image
COPY . /src
WORKDIR /src
RUN if [ "$BATTERY_SUPPORT" = "ON" ] ; then \
  	nix --extra-experimental-features "nix-command flakes" build .#YariloBattery; \
 	else \
  	nix --extra-experimental-features "nix-command flakes" build .; \
 	fi;

# Development image
FROM builder AS development

COPY <<EOF /run.sh
git config --global --add safe.directory /src
if [ "$BATTERY_SUPPORT" = "ON" ] ; then \
	nix --extra-experimental-features "nix-command flakes" build .#YariloBattery; \
	else \
	nix --extra-experimental-features "nix-command flakes" build .; \
	fi;
nix --extra-experimental-features "nix-command flakes" shell nixpkgs#envoy --command envoy -c /src/backend/envoy.yaml --log-path /app/envoy.log >/dev/null 2>&1 &
/src/result/bin/yarilo \$*
EOF

RUN chmod +x /run.sh
WORKDIR /src
EXPOSE 9090
ENTRYPOINT ["sh", "/run.sh"]

FROM builder AS production

COPY <<EOF /run.sh
inix --extra-experimental-features "nix-command flakes" shell nixpkgs#envoy --command envoy -c /src/backend/envoy.yaml --log-path /app/envoy.log >/dev/null 2>&1 &
/src/result/bin/yarilo \$*
EOF

RUN chmod +x /run.sh

EXPOSE 9090
ENTRYPOINT ["sh", "/run.sh"]
