#!/bin/sh

docker build -f ./km.Dockerfile --build-arg SGX_MODE=SW --rm -t enigmampc/enigma-cluster-km-sw:latest .
