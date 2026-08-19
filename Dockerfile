# Multi-stage Docker build for DorkForge (dfg)
# Stage 1: Build static binary
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Copy dependency definition
COPY go.mod ./

# Copy source tree
COPY . .

# Compile static binary with optimizations and stripped symbols
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -trimpath \
    -o dorkforge ./cmd/dorkforge

# Stage 2: Minimal runtime environment
FROM alpine:3.20

# Install root TLS certificates and timezone data
RUN apk --no-cache add ca-certificates tzdata

# Create unprivileged application user and directories
RUN addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S appuser -G appgroup && \
    mkdir -p /app/reports /app/targets && \
    chown -R appuser:appgroup /app

# Copy binary from builder
COPY --from=builder /build/dorkforge /usr/local/bin/dorkforge

# Create short alias symlink
RUN ln -sf /usr/local/bin/dorkforge /usr/local/bin/dfg

USER appuser:appgroup
WORKDIR /app

ENTRYPOINT ["dorkforge"]
CMD ["--help"]
