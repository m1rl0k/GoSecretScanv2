# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod ./

# Download dependencies
RUN go mod download

# Copy source code
COPY main.go ./

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o gosecretscanner main.go

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /workspace

# Copy the binary from builder
COPY --from=builder /build/gosecretscanner /usr/local/bin/gosecretscanner

# Make it executable
RUN chmod +x /usr/local/bin/gosecretscanner

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/gosecretscanner"]
