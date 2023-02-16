FROM golang:1.19-alpine as builder
# Add a work directory
WORKDIR /app
# Cache and install dependencies
COPY go.mod go.sum ./
RUN go mod download
# Copy app files
COPY . .
# Start app
RUN CGO_ENABLED=0 GOOS=linux go build cmd/main.go

# generate clean, final image for end users
FROM alpine:latest
COPY --from=builder /app/main .

# executable
ENTRYPOINT [ "./main" ]