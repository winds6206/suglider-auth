#!/bin/sh

STARTDIR=$(dirname "$(readlink -f ${0})")
cd "${STARTDIR}/.."

read -p 'Enter the timezone [Asia/Taipei]: ' TZ
TZ="${TZ:-Asia/Taipei}"

read -p 'Enter the golang version to build [1.21]: ' GO_VERSION
GO_VERSION=${GO_VER:-1.21}

read -p 'Enter the program version [0.0.1]: ' VERSION
VERSION="${VERSION:-0.0.1}"

read -p 'Enter the image name [suglider-auth]: ' DOCKER_IMAGE_NAME
DOCKER_IMAGE_NAME="${DOCKER_IMAGE_NAME:-suglider-auth}"

read -p 'Enter the image tag [latest]: ' TAG
TAG="${TAG:-latest}"

export TZ=${TZ}
export SERVICE_NAME=${DOCKER_IMAGE_NAME}
export VERSION=${VERSION}
export BUILD_DOC="-tags doc"
export GO_VERSION=${GO_VERSION}

docker build \
  --build-arg TZ \
  --build-arg GO_VERSION \
  --build-arg SERVICE_NAME \
  --build-arg VERSION \
  --build-arg BUILD_DOC \
  --tag "${DOCKER_IMAGE_NAME}:${TAG}" \
  --file ./build/Dockerfile \
  .
