# Use a small Go base image
FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o ext-authz .

# Final image
FROM alpine:3.22
RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=builder /app/ext-authz .

EXPOSE 50051

ENTRYPOINT ["./ext-authz"]
