# Build the ztc binary and package it in a minimal image.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /ztc ./cmd/ztc

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && adduser -D -u 1000 ztc
COPY --from=build /ztc /usr/local/bin/ztc
USER ztc
ENTRYPOINT ["ztc"]
CMD ["version"]
