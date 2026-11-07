#!/bin/bash

set -e

mkdir -p dist
mkdir -p wasm

npm run lint

if [[ "$(docker images -q clang:wasm-crypto-hash 2> /dev/null)" == "" ]]; then
  docker build -f scripts/Dockerfile -t clang:wasm-crypto-hash .
fi

# copy to docker volume
docker rm wasm-crypto-hash-temp || true
docker volume rm wasm-crypto-hash-volume || true
docker container create --name wasm-crypto-hash-temp -v wasm-crypto-hash-volume:/app busybox
docker cp . wasm-crypto-hash-temp:/app

docker run \
  --rm \
  -v wasm-crypto-hash-volume:/app \
  -u $(id -u):$(id -g) \
  clang:wasm-crypto-hash \
  make -f /app/scripts/Makefile-clang --silent --always-make --output-sync=target -j8 all

# copy output back
docker cp wasm-crypto-hash-temp:/app/wasm/ .
docker rm wasm-crypto-hash-temp
docker volume rm wasm-crypto-hash-volume

# node scripts/optimize
node scripts/make_json
node --max-old-space-size=4096 ./node_modules/rollup/dist/bin/rollup -c
npx tsc ./lib/index --outDir ./dist --downlevelIteration --emitDeclarationOnly --declaration --resolveJsonModule --allowSyntheticDefaultImports

#-s ASSERTIONS=1 \
