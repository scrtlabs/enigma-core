#!/usr/bin/env bash
SRC=$(pwd)/../
echo "Checking your SGX driver..."
ls /dev/isgx >/dev/null 2>1  && echo -e "SGX Driver installed\n" || echo -e "SGX Driver NOT installed\n"
echo "Running the Docker container..."
echo -e "Mapping local $SRC to container's /root/src/\n"
docker run --net="host" -it --mount src="$SRC",target=/root/src,type=bind --device /dev/isgx enigma-core
