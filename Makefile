.PHONY: all build test lint proto

all: build test lint

build: proto
	go build ./...

test:
	go test -v ./...

lint: bin/golangci-lint-1.23.8
	./bin/golangci-lint-1.23.8 run ./...

bin/golangci-lint-1.23.8:
	./hack/fetch-golangci-lint.sh

proto: proto/sshsigner/v1alpha1/sshsigner.pb.go \
		proto/sshsigner/v1alpha1/sshsigner.pb.gw.go \
		proto/sshsigner/v1alpha1/sshsigner.swagger.json  \
		proto/sshsigner/v1alpha1/httpclient

proto/sshsigner/v1alpha1/sshsigner.pb.go: proto/sshsigner/v1alpha1/sshsigner.proto proto/vendor/google/api/annotations.proto proto/vendor/google/api/http.proto
	go install github.com/golang/protobuf/protoc-gen-go
	protoc -Iproto -Iproto/vendor --go_out="plugins=grpc,paths=source_relative:proto" proto/sshsigner/v1alpha1/sshsigner.proto

proto/sshsigner/v1alpha1/sshsigner.pb.gw.go: proto/sshsigner/v1alpha1/sshsigner.proto
	go install github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway
	protoc -Iproto -Iproto/vendor --grpc-gateway_out="paths=source_relative:proto" proto/sshsigner/v1alpha1/sshsigner.proto

proto/sshsigner/v1alpha1/sshsigner.swagger.json: proto/sshsigner/v1alpha1/sshsigner.proto proto/sshsigner/v1alpha1/sshsigner_mixin.swagger.json
	go install github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger
	protoc -Iproto -Iproto/vendor  --swagger_out="logtostderr=true:proto" proto/sshsigner/v1alpha1/sshsigner.proto
	mv proto/sshsigner/v1alpha1/sshsigner.swagger.json proto/sshsigner/v1alpha1/sshsigner_gen.swagger.json
	cat proto/sshsigner/v1alpha1/sshsigner_gen.swagger.json proto/sshsigner/v1alpha1/sshsigner_mixin.swagger.json | jq --slurp 'reduce .[] as $$item ({}; . * $$item)' > proto/sshsigner/v1alpha1/sshsigner.swagger.json

proto/sshsigner/v1alpha1/httpclient: proto/sshsigner/v1alpha1/sshsigner.swagger.json
	go install github.com/go-swagger/go-swagger/cmd/swagger
	mkdir -p proto/sshsigner/v1alpha1/httpclient
	swagger generate client \
        -f "./proto/sshsigner/v1alpha1/sshsigner.swagger.json" \
        -t "./proto/sshsigner/v1alpha1/httpclient"
	touch proto/sshsigner/v1alpha1/httpclient

proto/vendor/google/api/annotations.proto:
	mkdir -p proto/vendor/google/api
	curl -sLo proto/vendor/google/api/annotations.proto https://github.com/googleapis/googleapis/raw/master/google/api/annotations.proto

proto/vendor/google/api/http.proto:
	mkdir -p proto/vendor/google/api
	curl -sLo proto/vendor/google/api/http.proto https://github.com/googleapis/googleapis/raw/master/google/api/http.proto
