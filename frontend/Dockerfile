# syntax=docker/dockerfile:1

FROM nixos/nix:2.23.0 AS base

# Image to capture store closure
FROM base AS production

# Building the project
COPY . /src
WORKDIR /src
RUN nix --extra-experimental-features "nix-command flakes" build .#YariloFrontend

EXPOSE 3000
ENTRYPOINT ["/src/result/bin/yarilo-frontend"]
