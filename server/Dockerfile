# syntax=docker/dockerfile:1.6

FROM golang:1.24 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/d-eyes-server ./cmd/server

FROM gcr.io/distroless/base-debian12:nonroot AS runtime

WORKDIR /app

COPY --from=build /out/d-eyes-server /usr/local/bin/d-eyes-server
COPY config /etc/d-eyes/config

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/d-eyes-server"]
CMD ["--config", "/etc/d-eyes/config/server.yaml"]
