FROM golang:1.19-alpine AS builder

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o app-test .
ENTRYPOINT ["/app/app-test"]
