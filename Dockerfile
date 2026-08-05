# Build stage
FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build \
    -ldflags="-s -w -X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)" \
    -o /threatlens \
    ./cmd/threatlens

# Runtime stage
FROM scratch
COPY --from=builder /threatlens /threatlens
COPY --from=builder /src/knowledge /knowledge
ENTRYPOINT ["/threatlens"]
CMD ["--help"]
