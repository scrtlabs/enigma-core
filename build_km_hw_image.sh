#!/bin/sh

docker build -f ./km.Dockerfile --build-arg SGX_MODE=HW --rm -t enigmampc/enigma-cluster-km-hw:latest .
