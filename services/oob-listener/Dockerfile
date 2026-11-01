FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.work go.work.sum ./
COPY pkg/ ./pkg/
COPY services/ ./services/

WORKDIR /app/services/oob-listener
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /vyomite-oob ./cmd

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /vyomite-oob .
EXPOSE 8082
ENTRYPOINT ["./vyomite-oob"]
