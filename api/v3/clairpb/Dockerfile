FROM golang:alpine

RUN apk add --update --no-cache git perl-utils curl bash protobuf-dev bash
SHELL [ "/bin/bash", "-c" ]

RUN go get -u github.com/gogo/protobuf/protoc-gen-gogoslick
RUN git clone https://github.com/gogo/googleapis /go/src/github.com/gogo/googleapis
RUN go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway
RUN go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger
RUN go get -u github.com/mwitkow/go-proto-validators/protoc-gen-govalidators
