#!/usr/bin/env bash
SRC=$(pwd)/../
echo "Checking your local /dev/isgx driver..."
ls /dev/isgx >/dev/null 2>1  && echo -e "SGX Driver installed\n" || echo -e "SGX Driver NOT installed\n"

echo -e "Removing existing enigma-core containers...\n"
docker ps -a | awk '{ print $1,$2 }' | grep enigma-core | awk '{print $1 }' | xargs -I {} docker rm {}

echo "Running the Docker container..."
echo -e "Mapping local $SRC to container's /root/src/\n"
docker run --net="host" -it -v "$SRC":/root/src:rw -v ~/.enigma:/root/.enigma:rw --device /dev/isgx --name enigma-core enigma-core
