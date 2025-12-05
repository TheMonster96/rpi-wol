FROM golang:tip-alpine3.23 as base

FROM debian:trixie-slim

RUN apt-get update 
RUN apt-get install -y openssh-server openssh-client \
    make \
    golang-go \
    openssl \
    ca-certificates 

WORKDIR /opt/rpi-wol

RUN mkdir .ssh

COPY ./authorized_keys.yaml .ssh
COPY  ./backend.go ./build.sh ./Makefile ./go.* . 

RUN go mod tidy

RUN /bin/bash -c ./build.sh

EXPOSE 2222
ENTRYPOINT ["backend"]
