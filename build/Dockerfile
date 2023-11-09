ARG GO_VERSION="1.21"

# Runtime
FROM alpine:latest AS runtime
ARG TZ="Asia/Taipei"
ENV TZ $TZ
RUN apk add -U --no-cache tzdata
RUN cp /usr/share/zoneinfo/$TZ /etc/localtime && echo "$TZ" > /etc/timezone
RUN adduser -S suglider && echo "suglider:suglider" | chpasswd suglider

# Builder
FROM golang:$GO_VERSION-alpine AS builder
ARG VERSION="0.0.1"
ARG BUILD_TAGS="doc"
ENV VERSION $VERSION
ENV BUILD_TAGS $BUILD_TAGS
ENV GO111MODULE on
ENV CGO_ENABLED 0
ENV GOOS linux
ENV GOARCH amd64
RUN mkdir -p /build
COPY ./ /build
WORKDIR /build
# RUN apk add -U --no-cache gcc musl-dev # for "-race" parameter
RUN go build -mod mod -o suglider-auth \
    -buildvcs=false \
    -tags=${BUILD_TAGS} \
    -ldflags="-X main.Version=${VERSION} -X main.Build=$(date +%F)"

# Minimized image
FROM runtime
RUN mkdir -p /usr/local/app/configs && \
    mkdir -p /usr/local/app/bin && \
    mkdir -p /usr/local/app/logs && \
    mkdir -p /usr/local/app/docs && \
    mkdir -p /usr/local/app/web
RUN chown suglider:root /usr/local/app/logs
COPY --from='builder' /build/suglider-auth /usr/local/app/bin/suglider-auth
COPY --from='builder' /build/configs/ /usr/local/app/configs
COPY --from='builder' /build/docs/ /usr/local/app/docs
COPY --from='builder' /build/web /usr/local/app/web
STOPSIGNAL SIGTERM
WORKDIR /usr/local/app
USER suglider
ENTRYPOINT /usr/local/app/bin/suglider-auth
