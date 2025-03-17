FROM golang:1.19-alpine AS builder

WORKDIR /build

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY *.go ./

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o openaipot .

# Use a small alpine image for the final container
FROM alpine:3.16

# Install necessary packages
RUN apk --no-cache add ca-certificates tzdata && \
    mkdir -p /app /var/log/openaipot

WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /build/openaipot .

# Create a non-root user to run the application
RUN addgroup -S openaipot && \
    adduser -S -G openaipot openaipot && \
    chown -R openaipot:openaipot /app /var/log/openaipot

# Use the non-root user
USER openaipot

# Set the entry point
ENTRYPOINT ["/app/openaipot"]