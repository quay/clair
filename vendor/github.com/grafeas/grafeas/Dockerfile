FROM golang:1.9
COPY . /go/src/github.com/grafeas/grafeas/
WORKDIR /go/src/github.com/grafeas/grafeas/samples/server/go-server/api/server/main
RUN CGO_ENABLED=0 go build -o grafeas-server .

FROM alpine:latest
WORKDIR /
COPY --from=0 /go/src/github.com/grafeas/grafeas/samples/server/go-server/api/server/main/grafeas-server /grafeas-server 
EXPOSE 8080
CMD ["/grafeas-server"]
