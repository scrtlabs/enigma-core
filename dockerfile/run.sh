#!/usr/bin/env bash
docker run --net="host" -it --mount src="$(pwd)/../",target=/root/src,type=bind --device /dev/isgx enigma-core
