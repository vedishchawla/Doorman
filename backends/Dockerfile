FROM golang:1.22.8-alpine3.20 AS builder
WORKDIR /build
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o backend .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /build/backend /backend
ENTRYPOINT ["/backend"]
