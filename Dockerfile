FROM golang:1.27 AS build
WORKDIR /src
COPY go.* ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/twig-cloud ./cmd/server
RUN mkdir /out/data

FROM gcr.io/distroless/static-debian12:nonroot
# /data must exist in the image, owned by the runtime user: Docker seeds new
# named volumes with the image directory's ownership, so without this a
# fresh volume is root-owned and the nonroot server cannot write the DB.
COPY --from=build --chown=nonroot:nonroot /out/data /data
COPY --from=build /out/twig-cloud /twig-cloud
ENV PORT=8080 \
    DATA_DIR=/data
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/twig-cloud"]
