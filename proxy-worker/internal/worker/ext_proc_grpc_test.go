package worker

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

func TestExtProcGRPCServerReturnsHeaderMutation(t *testing.T) {
	log := NewMemoryEventLog()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		_ = ServeExtProc(listener, testPolicy("api.example.test", 80), staticSecretProvider{value: "test-token"}, log)
	}()

	descs, err := newExtProcDescriptors()
	if err != nil {
		t.Fatal(err)
	}
	stream := openExtProcClientStream(t, listener.Addr().String())
	if err := stream.SendMsg(extProcRequestHeaders(t, descs, []Header{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: "api.example.test"},
		{Name: ":path", Value: "/v1/models"},
	})); err != nil {
		t.Fatal(err)
	}

	response := dynamicpb.NewMessage(descs.processingResponse)
	if err := stream.RecvMsg(response); err != nil {
		t.Fatal(err)
	}
	mutations := extProcResponseMutations(t, descs, response)
	if got := mutations["Authorization"]; got != "Bearer test-token" {
		t.Fatalf("Authorization mutation = %q, want injected token", got)
	}
	logs := strings.Join(log.Entries(), "\n")
	if strings.Contains(logs, "test-token") {
		t.Fatalf("logs leaked secret: %s", logs)
	}
}

func TestExtProcGRPCServerReturnsImmediateDeny(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		_ = ServeExtProc(listener, testPolicy("allowed.example.test", 80), staticSecretProvider{value: "test-token"}, NewMemoryEventLog())
	}()

	descs, err := newExtProcDescriptors()
	if err != nil {
		t.Fatal(err)
	}
	stream := openExtProcClientStream(t, listener.Addr().String())
	if err := stream.SendMsg(extProcRequestHeaders(t, descs, []Header{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: "denied.example.test"},
	})); err != nil {
		t.Fatal(err)
	}

	response := dynamicpb.NewMessage(descs.processingResponse)
	if err := stream.RecvMsg(response); err != nil {
		t.Fatal(err)
	}
	immediateField := descs.processingResponse.Fields().ByName("immediate_response")
	if !response.Has(immediateField) {
		t.Fatalf("response = %v, want immediate_response", response)
	}
	immediate := response.Get(immediateField).Message()
	details := immediate.Get(descs.immediateResponse.Fields().ByName("details")).String()
	if details != "airlock_egress_denied" {
		t.Fatalf("details = %q, want airlock_egress_denied", details)
	}
}

func TestExtProcGRPCServerSecretFailureReturnsImmediateError(t *testing.T) {
	log := NewMemoryEventLog()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		_ = ServeExtProc(listener, testPolicy("api.example.test", 80), failingSecretProvider{err: fmt.Errorf("vault unavailable")}, log)
	}()

	descs, err := newExtProcDescriptors()
	if err != nil {
		t.Fatal(err)
	}
	stream := openExtProcClientStream(t, listener.Addr().String())
	if err := stream.SendMsg(extProcRequestHeaders(t, descs, []Header{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: "api.example.test"},
		{Name: ":path", Value: "/v1/models"},
	})); err != nil {
		t.Fatal(err)
	}

	response := dynamicpb.NewMessage(descs.processingResponse)
	if err := stream.RecvMsg(response); err != nil {
		t.Fatal(err)
	}
	details := extProcImmediateDetails(t, descs, response)
	if !strings.Contains(details, "airlock_ext_proc_error") || !strings.Contains(details, "vault unavailable") {
		t.Fatalf("details = %q, want secret dependency error", details)
	}
	if strings.Contains(strings.Join(log.Entries(), "\n"), "allowed ext_proc request") {
		t.Fatalf("logs = %q, want no allowed request log", log.Entries())
	}
	if !strings.Contains(strings.Join(log.Entries(), "\n"), "dependency=secret") {
		t.Fatalf("logs = %q, want secret dependency log", log.Entries())
	}
}

func openExtProcClientStream(t *testing.T, addr string) grpc.ClientStream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{
		StreamName:    "Process",
		ServerStreams: true,
		ClientStreams: true,
	}, "/envoy.service.ext_proc.v3.ExternalProcessor/Process")
	if err != nil {
		t.Fatal(err)
	}
	return stream
}

func extProcImmediateDetails(t *testing.T, descs extProcDescriptors, response *dynamicpb.Message) string {
	t.Helper()
	immediateField := descs.processingResponse.Fields().ByName("immediate_response")
	if !response.Has(immediateField) {
		t.Fatalf("response = %v, want immediate_response", response)
	}
	immediate := response.Get(immediateField).Message()
	return immediate.Get(descs.immediateResponse.Fields().ByName("details")).String()
}

func extProcRequestHeaders(t *testing.T, descs extProcDescriptors, headers []Header) *dynamicpb.Message {
	t.Helper()
	request := dynamicpb.NewMessage(descs.processingRequest)
	httpHeaders := dynamicpb.NewMessage(descs.httpHeaders)
	headerMap := dynamicpb.NewMessage(descs.headerMap)
	headerList := headerMap.Mutable(descs.headerMap.Fields().ByName("headers")).List()
	for _, header := range headers {
		headerValue := dynamicpb.NewMessage(descs.headerValue)
		headerValue.Set(descs.headerValue.Fields().ByName("key"), protoreflect.ValueOfString(header.Name))
		headerValue.Set(descs.headerValue.Fields().ByName("value"), protoreflect.ValueOfString(header.Value))
		headerList.Append(protoreflect.ValueOfMessage(headerValue))
	}
	httpHeaders.Set(descs.httpHeaders.Fields().ByName("headers"), protoreflect.ValueOfMessage(headerMap))
	request.Set(descs.processingRequest.Fields().ByName("request_headers"), protoreflect.ValueOfMessage(httpHeaders))
	return request
}

func extProcResponseMutations(t *testing.T, descs extProcDescriptors, response *dynamicpb.Message) map[string]string {
	t.Helper()
	requestHeadersField := descs.processingResponse.Fields().ByName("request_headers")
	if !response.Has(requestHeadersField) {
		t.Fatalf("response = %v, want request_headers", response)
	}
	headersResponse := response.Get(requestHeadersField).Message()
	common := headersResponse.Get(descs.headersResponse.Fields().ByName("response")).Message()
	mutation := common.Get(descs.commonResponse.Fields().ByName("header_mutation")).Message()
	setHeaders := mutation.Get(descs.headerMutation.Fields().ByName("set_headers")).List()
	got := map[string]string{}
	for i := 0; i < setHeaders.Len(); i++ {
		option := setHeaders.Get(i).Message()
		header := option.Get(descs.headerValueOption.Fields().ByName("header")).Message()
		name := header.Get(descs.headerValue.Fields().ByName("key")).String()
		value := header.Get(descs.headerValue.Fields().ByName("value")).String()
		rawValue := header.Get(descs.headerValue.Fields().ByName("raw_value")).Bytes()
		if value == "" && len(rawValue) > 0 {
			value = string(rawValue)
		}
		got[name] = value
	}
	return got
}
