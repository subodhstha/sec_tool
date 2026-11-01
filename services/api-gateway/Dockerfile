FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.work go.work.sum ./
COPY pkg/ ./pkg/
COPY services/ ./services/

WORKDIR /app/services/api-gateway
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /vyomite-api ./cmd

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /vyomite-api .
EXPOSE 8080
ENTRYPOINT ["./vyomite-api"]
