#!/bin/sh

docker build -f ./core.Dockerfile --build-arg SGX_MODE=HW --rm -t enigmampc/enigma-cluster-core-hw:latest .
