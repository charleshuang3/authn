# Stage 1: Build the Go binary
FROM golang:1.24 AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o authn ./cmd/authn/main.go

# Stage 2: Create a minimal runtime image
FROM alpine:3.21

WORKDIR /app

# Install ca-certificates for SSL/TLS support
RUN apk update && apk add --no-cache ca-certificates

# Copy the binary from the builder stage
COPY --from=builder /app/authn .

# Command to run the executable
CMD ["./authn"]
