package agentservicepb

//go:generate sh -c "protoc --proto_path=.. --go_out=. --go_opt=paths=source_relative --plugin=protoc-gen-go=$(go env GOPATH)/bin/protoc-gen-go --go-grpc_out=. --go-grpc_opt=paths=source_relative --plugin=protoc-gen-go-grpc=$(go env GOPATH)/bin/protoc-gen-go-grpc ../agentservice.proto"
