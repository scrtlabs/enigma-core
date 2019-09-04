#!/bin/sh

docker build -f ./core.Dockerfile --build-arg SGX_MODE=SW --rm -t enigmampc/enigma-cluster-core-sw:latest .
