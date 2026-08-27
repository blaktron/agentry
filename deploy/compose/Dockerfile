# agentryd container image (self-host + SaaS base). Minimal, non-root (§13.3).
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/agentryd ./cmd/agentryd

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/agentryd /usr/bin/agentryd
USER nonroot
ENTRYPOINT ["/usr/bin/agentryd"]
CMD ["all"]
