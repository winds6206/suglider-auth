BINARY_NAME = suglider-auth
VERSION     = 0.0.1
BUILD_DATE  = $(shell date +%F)
BUILD_TAGS  = doc
BUILD_FLAGS = "-X main.Version=${VERSION} -X main.Build=${BUILD_DATE}"
TZ          = Asia/Taipei
GO_VERSION  = 1.21
CONFIG_FILE = configs/configuration/dev.toml

.PHONY: build
build:
	GOARCH=amd64 CGO_ENABLED=0 \
	go build -mod mod -buildvcs=false -tags ${BUILD_TAGS} -ldflags ${BUILD_FLAGS} \
	-o bin/${BINARY_NAME}

run:
	go mod tidy
	go run -race -mod mod -buildvcs=false -tags ${BUILD_TAGS} -ldflags ${BUILD_FLAGS} . \
	-c ${CONFIG_FILE}

clean:
	go clean
	go clean -testcache
	@if [ -f bin/${BINARY_NAME} ] ; then rm -f bin/${BINARY_NAME} ; fi
	@if [ -f bin/mailer ] ; then rm -rf bin/mailer ; fi

docker:
	docker buildx build --no-cache \
	--build-arg "TZ=${TZ}" \
	--build-arg "GO_VERSION=${GO_VERSION}" \
	--build-arg "VERSION=${VERSION}" \
	--build-arg "BUILD_TAGS=${BUILD_TAGS}" \
	--tag "${BINARY_NAME}:${VERSION}" \
	--tag "${BINARY_NAME}:latest" \
	--file build/Dockerfile \
	.

lint:
	golangci-lint run --verbose

benchmark:
	go mod tidy
	go test -bench=.

.PHONY: test
test:
	go mod tidy
	go test -race -v ./...

mailer:
	go build -o bin/mailer ./cmd/mailer

sms_sender:
	go build -o bin/sms_sender ./cmd/sms_sender

help:
	@echo "make build VERSION=1.0.0 - compile the binary file with golang codes"
	@echo "make docker VERSION=1.0.0 GO_VERSION=1.21 - compile the docker image from build/Dockerfile"
	@echo "make clean - remove the binary file in the bin directory"
	@echo "make lint - check golang syntax"
	@echo "make benchmark - run benchmark"
	@echo "make test - run test with -race parameter"
	@echo "make run CONFIG_FILE=path/to/config.toml - run the service with specific config file"
	@echo "make mailer - build a simple tool for sending mail by smtp"
	@echo "make sms_sender - build a simple tool for sending message by sms"

