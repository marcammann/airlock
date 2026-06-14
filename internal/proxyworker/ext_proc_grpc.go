package proxyworker

import (
	"fmt"
	"io"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

const extProcServiceName = "envoy.service.ext_proc.v3.ExternalProcessor"

type ExtProcGRPCServer struct {
	policy  CompiledPolicy
	secrets SecretProvider
	log     *EventLog
	descs   extProcDescriptors
}

func NewExtProcGRPCServer(policy CompiledPolicy, secrets SecretProvider, log *EventLog) (*ExtProcGRPCServer, error) {
	if log == nil {
		log = NewEventLog(io.Discard)
	}
	descs, err := newExtProcDescriptors()
	if err != nil {
		return nil, err
	}
	return &ExtProcGRPCServer{policy: policy, secrets: secrets, log: log, descs: descs}, nil
}

func ServeExtProc(listener net.Listener, policy CompiledPolicy, secrets SecretProvider, log *EventLog) error {
	service, err := NewExtProcGRPCServer(policy, secrets, log)
	if err != nil {
		return err
	}
	server := grpc.NewServer()
	RegisterExternalProcessorServer(server, service)
	return server.Serve(listener)
}

func RegisterExternalProcessorServer(server *grpc.Server, service *ExtProcGRPCServer) {
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: extProcServiceName,
		HandlerType: (*externalProcessorServer)(nil),
		Streams: []grpc.StreamDesc{{
			StreamName:    "Process",
			Handler:       extProcProcessHandler,
			ServerStreams: true,
			ClientStreams: true,
		}},
		Metadata: "envoy/service/ext_proc/v3/external_processor.proto",
	}, service)
}

func extProcProcessHandler(srv any, stream grpc.ServerStream) error {
	return srv.(externalProcessorServer).Process(stream)
}

type externalProcessorServer interface {
	Process(grpc.ServerStream) error
}

func (s *ExtProcGRPCServer) Process(stream grpc.ServerStream) error {
	for {
		request := dynamicpb.NewMessage(s.descs.processingRequest)
		if err := stream.RecvMsg(request); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		response := s.processDynamicRequest(request)
		if err := stream.SendMsg(response); err != nil {
			return err
		}
	}
}

func (s *ExtProcGRPCServer) processDynamicRequest(request *dynamicpb.Message) *dynamicpb.Message {
	requestHeadersField := s.descs.processingRequest.Fields().ByName("request_headers")
	if !request.Has(requestHeadersField) {
		return s.continueResponse(nil)
	}
	headers := s.headersFromHTTPHeaders(request.Get(requestHeadersField).Message())
	decision, err := EvaluateExtProcHeaders(s.policy, headers, s.secrets, s.log)
	if err != nil {
		return s.immediateResponse(500, []byte("airlock ext_proc error"), fmt.Sprintf("airlock_ext_proc_error: %v", err))
	}
	if decision.Continue {
		return s.continueResponse(decision.Mutations)
	}
	return s.immediateResponse(int(decision.Status), []byte(decision.Body), decision.Details)
}

func (s *ExtProcGRPCServer) headersFromHTTPHeaders(httpHeaders protoreflect.Message) []Header {
	headerMapField := s.descs.httpHeaders.Fields().ByName("headers")
	if !httpHeaders.Has(headerMapField) {
		return nil
	}
	headerMap := httpHeaders.Get(headerMapField).Message()
	headersField := s.descs.headerMap.Fields().ByName("headers")
	values := headerMap.Get(headersField).List()
	headers := make([]Header, 0, values.Len())
	keyField := s.descs.headerValue.Fields().ByName("key")
	valueField := s.descs.headerValue.Fields().ByName("value")
	rawValueField := s.descs.headerValue.Fields().ByName("raw_value")
	for i := 0; i < values.Len(); i++ {
		header := values.Get(i).Message()
		value := header.Get(valueField).String()
		rawValue := header.Get(rawValueField).Bytes()
		if value == "" && len(rawValue) > 0 {
			value = string(rawValue)
		}
		headers = append(headers, Header{
			Name:  header.Get(keyField).String(),
			Value: value,
		})
	}
	return headers
}

func (s *ExtProcGRPCServer) continueResponse(mutations []Header) *dynamicpb.Message {
	response := dynamicpb.NewMessage(s.descs.processingResponse)
	headersResponse := dynamicpb.NewMessage(s.descs.headersResponse)
	common := dynamicpb.NewMessage(s.descs.commonResponse)
	mutation := dynamicpb.NewMessage(s.descs.headerMutation)

	setHeadersField := s.descs.headerMutation.Fields().ByName("set_headers")
	setHeaders := mutation.Mutable(setHeadersField).List()
	for _, header := range mutations {
		setHeaders.Append(protoreflect.ValueOfMessage(s.headerValueOption(header)))
	}

	common.Set(s.descs.commonResponse.Fields().ByName("status"), protoreflect.ValueOfEnum(0))
	common.Set(s.descs.commonResponse.Fields().ByName("header_mutation"), protoreflect.ValueOfMessage(mutation))
	headersResponse.Set(s.descs.headersResponse.Fields().ByName("response"), protoreflect.ValueOfMessage(common))
	response.Set(s.descs.processingResponse.Fields().ByName("request_headers"), protoreflect.ValueOfMessage(headersResponse))
	return response
}

func (s *ExtProcGRPCServer) headerValueOption(header Header) protoreflect.Message {
	headerValue := dynamicpb.NewMessage(s.descs.headerValue)
	headerValue.Set(s.descs.headerValue.Fields().ByName("key"), protoreflect.ValueOfString(header.Name))
	headerValue.Set(s.descs.headerValue.Fields().ByName("raw_value"), protoreflect.ValueOfBytes([]byte(header.Value)))

	option := dynamicpb.NewMessage(s.descs.headerValueOption)
	option.Set(s.descs.headerValueOption.Fields().ByName("header"), protoreflect.ValueOfMessage(headerValue))
	option.Set(s.descs.headerValueOption.Fields().ByName("append_action"), protoreflect.ValueOfInt32(2))
	return option
}

func (s *ExtProcGRPCServer) immediateResponse(status int, body []byte, details string) *dynamicpb.Message {
	response := dynamicpb.NewMessage(s.descs.processingResponse)
	immediate := dynamicpb.NewMessage(s.descs.immediateResponse)
	httpStatus := dynamicpb.NewMessage(s.descs.httpStatus)

	httpStatus.Set(s.descs.httpStatus.Fields().ByName("code"), protoreflect.ValueOfEnum(protoreflect.EnumNumber(status)))
	immediate.Set(s.descs.immediateResponse.Fields().ByName("status"), protoreflect.ValueOfMessage(httpStatus))
	immediate.Set(s.descs.immediateResponse.Fields().ByName("body"), protoreflect.ValueOfBytes(body))
	immediate.Set(s.descs.immediateResponse.Fields().ByName("details"), protoreflect.ValueOfString(details))
	response.Set(s.descs.processingResponse.Fields().ByName("immediate_response"), protoreflect.ValueOfMessage(immediate))
	return response
}

type extProcDescriptors struct {
	processingRequest  protoreflect.MessageDescriptor
	processingResponse protoreflect.MessageDescriptor
	httpHeaders        protoreflect.MessageDescriptor
	headerMap          protoreflect.MessageDescriptor
	headerValue        protoreflect.MessageDescriptor
	headersResponse    protoreflect.MessageDescriptor
	commonResponse     protoreflect.MessageDescriptor
	headerMutation     protoreflect.MessageDescriptor
	headerValueOption  protoreflect.MessageDescriptor
	immediateResponse  protoreflect.MessageDescriptor
	httpStatus         protoreflect.MessageDescriptor
}

func newExtProcDescriptors() (extProcDescriptors, error) {
	file, err := protodesc.NewFile(extProcFileDescriptor(), nil)
	if err != nil {
		return extProcDescriptors{}, fmt.Errorf("build ext_proc descriptors: %w", err)
	}
	messages := file.Messages()
	lookup := func(name protoreflect.Name) protoreflect.MessageDescriptor {
		return messages.ByName(name)
	}
	return extProcDescriptors{
		processingRequest:  lookup("ProcessingRequest"),
		processingResponse: lookup("ProcessingResponse"),
		httpHeaders:        lookup("HttpHeaders"),
		headerMap:          lookup("HeaderMap"),
		headerValue:        lookup("HeaderValue"),
		headersResponse:    lookup("HeadersResponse"),
		commonResponse:     lookup("CommonResponse"),
		headerMutation:     lookup("HeaderMutation"),
		headerValueOption:  lookup("HeaderValueOption"),
		immediateResponse:  lookup("ImmediateResponse"),
		httpStatus:         lookup("HttpStatus"),
	}, nil
}

func extProcFileDescriptor() *descriptorpb.FileDescriptorProto {
	return &descriptorpb.FileDescriptorProto{
		Name:    proto.String("envoy/service/ext_proc/v3/external_processor.proto"),
		Package: proto.String("envoy.service.ext_proc.v3"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			message("ProcessingRequest",
				oneof("request"),
				fieldMsg("request_headers", 2, ".envoy.service.ext_proc.v3.HttpHeaders", oneofIndex(0)),
			),
			message("ProcessingResponse",
				oneof("response"),
				fieldMsg("request_headers", 1, ".envoy.service.ext_proc.v3.HeadersResponse", oneofIndex(0)),
				fieldMsg("immediate_response", 7, ".envoy.service.ext_proc.v3.ImmediateResponse", oneofIndex(0)),
			),
			message("HttpHeaders",
				fieldMsg("headers", 1, ".envoy.service.ext_proc.v3.HeaderMap", nil),
				fieldBool("end_of_stream", 3),
			),
			message("HeaderMap",
				repeatedMsg("headers", 1, ".envoy.service.ext_proc.v3.HeaderValue"),
			),
			message("HeaderValue",
				fieldString("key", 1),
				fieldString("value", 2),
				fieldBytes("raw_value", 3),
			),
			message("HeadersResponse",
				fieldMsg("response", 1, ".envoy.service.ext_proc.v3.CommonResponse", nil),
			),
			message("CommonResponse",
				enum("ResponseStatus", enumValue("CONTINUE", 0), enumValue("CONTINUE_AND_REPLACE", 1)),
				fieldEnum("status", 1, ".envoy.service.ext_proc.v3.CommonResponse.ResponseStatus"),
				fieldMsg("header_mutation", 2, ".envoy.service.ext_proc.v3.HeaderMutation", nil),
			),
			message("HeaderMutation",
				repeatedMsg("set_headers", 1, ".envoy.service.ext_proc.v3.HeaderValueOption"),
				repeatedString("remove_headers", 2),
			),
			message("HeaderValueOption",
				fieldMsg("header", 1, ".envoy.service.ext_proc.v3.HeaderValue", nil),
				fieldInt32("append_action", 3),
				fieldBool("keep_empty_value", 4),
			),
			message("ImmediateResponse",
				fieldMsg("status", 1, ".envoy.service.ext_proc.v3.HttpStatus", nil),
				fieldMsg("headers", 2, ".envoy.service.ext_proc.v3.HeaderMutation", nil),
				fieldBytes("body", 3),
				fieldString("details", 5),
			),
			message("HttpStatus",
				fieldEnum("code", 1, ".envoy.service.ext_proc.v3.StatusCode"),
			),
		},
		EnumType: []*descriptorpb.EnumDescriptorProto{
			enum("StatusCode",
				enumValue("Empty", 0),
				enumValue("OK", 200),
				enumValue("BadRequest", 400),
				enumValue("Forbidden", 403),
				enumValue("InternalServerError", 500),
			),
		},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("ExternalProcessor"),
			Method: []*descriptorpb.MethodDescriptorProto{{
				Name:            proto.String("Process"),
				InputType:       proto.String(".envoy.service.ext_proc.v3.ProcessingRequest"),
				OutputType:      proto.String(".envoy.service.ext_proc.v3.ProcessingResponse"),
				ClientStreaming: proto.Bool(true),
				ServerStreaming: proto.Bool(true),
			}},
		}},
	}
}

func message(name string, parts ...any) *descriptorpb.DescriptorProto {
	msg := &descriptorpb.DescriptorProto{Name: proto.String(name)}
	for _, part := range parts {
		switch v := part.(type) {
		case *descriptorpb.FieldDescriptorProto:
			msg.Field = append(msg.Field, v)
		case *descriptorpb.OneofDescriptorProto:
			msg.OneofDecl = append(msg.OneofDecl, v)
		case *descriptorpb.EnumDescriptorProto:
			msg.EnumType = append(msg.EnumType, v)
		}
	}
	return msg
}

func oneof(name string) *descriptorpb.OneofDescriptorProto {
	return &descriptorpb.OneofDescriptorProto{Name: proto.String(name)}
}

func enum(name string, values ...*descriptorpb.EnumValueDescriptorProto) *descriptorpb.EnumDescriptorProto {
	return &descriptorpb.EnumDescriptorProto{Name: proto.String(name), Value: values}
}

func enumValue(name string, number int32) *descriptorpb.EnumValueDescriptorProto {
	return &descriptorpb.EnumValueDescriptorProto{Name: proto.String(name), Number: proto.Int32(number)}
}

func oneofIndex(index int32) *int32 {
	return proto.Int32(index)
}

func fieldMsg(name string, number int32, typeName string, oneof *int32) *descriptorpb.FieldDescriptorProto {
	return field(name, number, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, typeName, oneof)
}

func repeatedMsg(name string, number int32, typeName string) *descriptorpb.FieldDescriptorProto {
	return field(name, number, descriptorpb.FieldDescriptorProto_LABEL_REPEATED, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, typeName, nil)
}

func fieldEnum(name string, number int32, typeName string) *descriptorpb.FieldDescriptorProto {
	return field(name, number, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL, descriptorpb.FieldDescriptorProto_TYPE_ENUM, typeName, nil)
}

func fieldString(name string, number int32) *descriptorpb.FieldDescriptorProto {
	return field(name, number, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL, descriptorpb.FieldDescriptorProto_TYPE_STRING, "", nil)
}

func repeatedString(name string, number int32) *descriptorpb.FieldDescriptorProto {
	return field(name, number, descriptorpb.FieldDescriptorProto_LABEL_REPEATED, descriptorpb.FieldDescriptorProto_TYPE_STRING, "", nil)
}

func fieldBytes(name string, number int32) *descriptorpb.FieldDescriptorProto {
	return field(name, number, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL, descriptorpb.FieldDescriptorProto_TYPE_BYTES, "", nil)
}

func fieldBool(name string, number int32) *descriptorpb.FieldDescriptorProto {
	return field(name, number, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL, descriptorpb.FieldDescriptorProto_TYPE_BOOL, "", nil)
}

func fieldInt32(name string, number int32) *descriptorpb.FieldDescriptorProto {
	return field(name, number, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL, descriptorpb.FieldDescriptorProto_TYPE_INT32, "", nil)
}

func field(name string, number int32, label descriptorpb.FieldDescriptorProto_Label, kind descriptorpb.FieldDescriptorProto_Type, typeName string, oneof *int32) *descriptorpb.FieldDescriptorProto {
	fd := &descriptorpb.FieldDescriptorProto{
		Name:   proto.String(name),
		Number: proto.Int32(number),
		Label:  &label,
		Type:   &kind,
	}
	if typeName != "" {
		fd.TypeName = proto.String(typeName)
	}
	if oneof != nil {
		fd.OneofIndex = oneof
	}
	return fd
}
