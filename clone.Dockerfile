FROM alpine

RUN apk --update add git less openssh && \
    rm -rf /var/lib/apt/lists/* && \
    rm /var/cache/apk/*

COPY . /enigma-core/

# use with:
# docker build -f clone.Dockerfile -t gitclone_core .
