# This is a Makefile which maintains files automatically generated but to be
# shipped together with other files.
# You don't have to rebuild these targets by yourself unless you develop
# grpc-gateway itself.

PKG=github.com/grpc-ecosystem/grpc-gateway
GO_PLUGIN=bin/protoc-gen-go
GO_PROTOBUF_REPO=github.com/golang/protobuf
GO_PLUGIN_PKG=$(GO_PROTOBUF_REPO)/protoc-gen-go
GO_PTYPES_ANY_PKG=$(GO_PROTOBUF_REPO)/ptypes/any
SWAGGER_PLUGIN=bin/protoc-gen-swagger
SWAGGER_PLUGIN_SRC= utilities/doc.go \
		    utilities/pattern.go \
		    utilities/trie.go \
		    protoc-gen-swagger/genswagger/generator.go \
		    protoc-gen-swagger/genswagger/template.go \
		    protoc-gen-swagger/main.go
SWAGGER_PLUGIN_PKG=$(PKG)/protoc-gen-swagger
GATEWAY_PLUGIN=bin/protoc-gen-grpc-gateway
GATEWAY_PLUGIN_PKG=$(PKG)/protoc-gen-grpc-gateway
GATEWAY_PLUGIN_SRC= utilities/doc.go \
		    utilities/pattern.go \
		    utilities/trie.go \
		    protoc-gen-grpc-gateway \
		    protoc-gen-grpc-gateway/descriptor \
		    protoc-gen-grpc-gateway/descriptor/registry.go \
		    protoc-gen-grpc-gateway/descriptor/services.go \
		    protoc-gen-grpc-gateway/descriptor/types.go \
		    protoc-gen-grpc-gateway/generator \
		    protoc-gen-grpc-gateway/generator/generator.go \
		    protoc-gen-grpc-gateway/gengateway \
		    protoc-gen-grpc-gateway/gengateway/doc.go \
		    protoc-gen-grpc-gateway/gengateway/generator.go \
		    protoc-gen-grpc-gateway/gengateway/template.go \
		    protoc-gen-grpc-gateway/httprule \
		    protoc-gen-grpc-gateway/httprule/compile.go \
		    protoc-gen-grpc-gateway/httprule/parse.go \
		    protoc-gen-grpc-gateway/httprule/types.go \
		    protoc-gen-grpc-gateway/main.go
GATEWAY_PLUGIN_FLAGS?=

GOOGLEAPIS_DIR=third_party/googleapis
OUTPUT_DIR=_output

RUNTIME_PROTO=runtime/internal/stream_chunk.proto
RUNTIME_GO=$(RUNTIME_PROTO:.proto=.pb.go)

OPENAPIV2_PROTO=protoc-gen-swagger/options/openapiv2.proto protoc-gen-swagger/options/annotations.proto
OPENAPIV2_GO=$(OPENAPIV2_PROTO:.proto=.pb.go)

PKGMAP=Mgoogle/protobuf/descriptor.proto=$(GO_PLUGIN_PKG)/descriptor,Mexamples/proto/sub/message.proto=$(PKG)/examples/proto/sub
ADDITIONAL_FLAGS=
ifneq "$(GATEWAY_PLUGIN_FLAGS)" ""
	ADDITIONAL_FLAGS=,$(GATEWAY_PLUGIN_FLAGS)
endif
SWAGGER_EXAMPLES=examples/proto/examplepb/echo_service.proto \
	 examples/proto/examplepb/a_bit_of_everything.proto \
	 examples/proto/examplepb/wrappers.proto
EXAMPLES=examples/proto/examplepb/echo_service.proto \
	 examples/proto/examplepb/a_bit_of_everything.proto \
	 examples/proto/examplepb/stream.proto \
	 examples/proto/examplepb/flow_combination.proto \
	 examples/proto/examplepb/wrappers.proto
EXAMPLE_SVCSRCS=$(EXAMPLES:.proto=.pb.go)
EXAMPLE_GWSRCS=$(EXAMPLES:.proto=.pb.gw.go)
EXAMPLE_SWAGGERSRCS=$(SWAGGER_EXAMPLES:.proto=.swagger.json)
EXAMPLE_DEPS=examples/proto/sub/message.proto examples/proto/sub2/message.proto
EXAMPLE_DEPSRCS=$(EXAMPLE_DEPS:.proto=.pb.go)

EXAMPLE_CLIENT_DIR=examples/clients
ECHO_EXAMPLE_SPEC=examples/proto/examplepb/echo_service.swagger.json
ECHO_EXAMPLE_SRCS=$(EXAMPLE_CLIENT_DIR)/echo/api_client.go \
		  $(EXAMPLE_CLIENT_DIR)/echo/api_response.go \
		  $(EXAMPLE_CLIENT_DIR)/echo/configuration.go \
		  $(EXAMPLE_CLIENT_DIR)/echo/echo_service_api.go \
		  $(EXAMPLE_CLIENT_DIR)/echo/examplepb_simple_message.go
ABE_EXAMPLE_SPEC=examples/proto/examplepb/a_bit_of_everything.swagger.json
ABE_EXAMPLE_SRCS=$(EXAMPLE_CLIENT_DIR)/abe/a_bit_of_everything_nested.go \
		 $(EXAMPLE_CLIENT_DIR)/abe/a_bit_of_everything_service_api.go \
		 $(EXAMPLE_CLIENT_DIR)/abe/api_client.go \
		 $(EXAMPLE_CLIENT_DIR)/abe/api_response.go \
		 $(EXAMPLE_CLIENT_DIR)/abe/camel_case_service_name_api.go \
		 $(EXAMPLE_CLIENT_DIR)/abe/configuration.go \
		 $(EXAMPLE_CLIENT_DIR)/abe/echo_rpc_api.go \
		 $(EXAMPLE_CLIENT_DIR)/abe/echo_service_api.go \
		 $(EXAMPLE_CLIENT_DIR)/abe/examplepb_a_bit_of_everything.go \
		 $(EXAMPLE_CLIENT_DIR)/abe/examplepb_body.go \
		 $(EXAMPLE_CLIENT_DIR)/abe/examplepb_numeric_enum.go \
		 $(EXAMPLE_CLIENT_DIR)/abe/nested_deep_enum.go \
		 $(EXAMPLE_CLIENT_DIR)/abe/protobuf_empty.go \
		 $(EXAMPLE_CLIENT_DIR)/abe/sub_string_message.go
EXAMPLE_CLIENT_SRCS=$(ECHO_EXAMPLE_SRCS) $(ABE_EXAMPLE_SRCS)
SWAGGER_CODEGEN=swagger-codegen

PROTOC_INC_PATH=$(dir $(shell which protoc))/../include

generate: $(RUNTIME_GO)

.SUFFIXES: .go .proto

$(GO_PLUGIN):
	go get $(GO_PLUGIN_PKG)
	go build -o $@ $(GO_PLUGIN_PKG)

$(RUNTIME_GO): $(RUNTIME_PROTO) $(GO_PLUGIN)
	protoc -I $(PROTOC_INC_PATH) --plugin=$(GO_PLUGIN) -I $(GOPATH)/src/$(GO_PTYPES_ANY_PKG) -I. --go_out=$(PKGMAP):. $(RUNTIME_PROTO)

$(OPENAPIV2_GO): $(OPENAPIV2_PROTO) $(GO_PLUGIN)
	protoc -I $(PROTOC_INC_PATH) --plugin=$(GO_PLUGIN) -I. --go_out=$(PKGMAP):$(GOPATH)/src $(OPENAPIV2_PROTO)

$(GATEWAY_PLUGIN): $(RUNTIME_GO) $(GATEWAY_PLUGIN_SRC)
	go build -o $@ $(GATEWAY_PLUGIN_PKG)

$(SWAGGER_PLUGIN): $(SWAGGER_PLUGIN_SRC) $(OPENAPIV2_GO)
	go build -o $@ $(SWAGGER_PLUGIN_PKG)

$(EXAMPLE_SVCSRCS): $(GO_PLUGIN) $(EXAMPLES)
	protoc -I $(PROTOC_INC_PATH) -I. -I$(GOOGLEAPIS_DIR) --plugin=$(GO_PLUGIN) --go_out=$(PKGMAP),plugins=grpc:. $(EXAMPLES)
$(EXAMPLE_DEPSRCS): $(GO_PLUGIN) $(EXAMPLE_DEPS)
	mkdir -p $(OUTPUT_DIR)
	protoc -I $(PROTOC_INC_PATH) -I. --plugin=$(GO_PLUGIN) --go_out=$(PKGMAP),plugins=grpc:$(OUTPUT_DIR) $(@:.pb.go=.proto)
	cp $(OUTPUT_DIR)/$(PKG)/$@ $@ || cp $(OUTPUT_DIR)/$@ $@
$(EXAMPLE_GWSRCS): $(GATEWAY_PLUGIN) $(EXAMPLES)
	protoc -I $(PROTOC_INC_PATH) -I. -I$(GOOGLEAPIS_DIR) --plugin=$(GATEWAY_PLUGIN) --grpc-gateway_out=logtostderr=true,$(PKGMAP)$(ADDITIONAL_FLAGS):. $(EXAMPLES)
$(EXAMPLE_SWAGGERSRCS): $(SWAGGER_PLUGIN) $(SWAGGER_EXAMPLES)
	protoc -I $(PROTOC_INC_PATH) -I. -I$(GOOGLEAPIS_DIR) --plugin=$(SWAGGER_PLUGIN) --swagger_out=logtostderr=true,$(PKGMAP):. $(SWAGGER_EXAMPLES)

$(ECHO_EXAMPLE_SRCS): $(ECHO_EXAMPLE_SPEC)
	$(SWAGGER_CODEGEN) generate -i $(ECHO_EXAMPLE_SPEC) \
	    -l go -o examples/clients/echo --additional-properties packageName=echo
	@rm -f $(EXAMPLE_CLIENT_DIR)/echo/README.md \
		$(EXAMPLE_CLIENT_DIR)/echo/git_push.sh \
		$(EXAMPLE_CLIENT_DIR)/echo/.travis.yml
$(ABE_EXAMPLE_SRCS): $(ABE_EXAMPLE_SPEC)
	$(SWAGGER_CODEGEN) generate -i $(ABE_EXAMPLE_SPEC) \
	    -l go -o examples/clients/abe --additional-properties packageName=abe
	@rm -f $(EXAMPLE_CLIENT_DIR)/abe/README.md \
		$(EXAMPLE_CLIENT_DIR)/abe/git_push.sh \
		$(EXAMPLE_CLIENT_DIR)/abe/.travis.yml

examples: $(EXAMPLE_SVCSRCS) $(EXAMPLE_GWSRCS) $(EXAMPLE_DEPSRCS) $(EXAMPLE_SWAGGERSRCS) $(EXAMPLE_CLIENT_SRCS)
test: examples
	go test -race $(PKG)/...
	go test -race $(PKG)/examples/integration -args -network=unix -endpoint=test.sock

lint:
	golint --set_exit_status $(PKG)/runtime
	golint --set_exit_status $(PKG)/utilities/...
	golint --set_exit_status $(PKG)/protoc-gen-grpc-gateway/...
	golint --set_exit_status $(PKG)/protoc-gen-swagger/...
	go vet $(PKG)/runtime || true
	go vet $(PKG)/utilities/...
	go vet $(PKG)/protoc-gen-grpc-gateway/...
	go vet $(PKG)/protoc-gen-swagger/...

clean:
	rm -f $(GATEWAY_PLUGIN) $(SWAGGER_PLUGIN)
distclean: clean
	rm -f $(GO_PLUGIN)
realclean: distclean
	rm -f $(EXAMPLE_SVCSRCS) $(EXAMPLE_DEPSRCS)
	rm -f $(EXAMPLE_GWSRCS)
	rm -f $(EXAMPLE_SWAGGERSRCS)
	rm -f $(EXAMPLE_CLIENT_SRCS)
	rm -f $(OPENAPIV2_GO)

.PHONY: generate examples test lint clean distclean realclean
