package worker

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"
)

const envoySecretTypeURL = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"

func ServeEnvoy(listener net.Listener, policy CompiledPolicy, secrets SecretProvider, log *EventLog, ca *CertificateAuthority) error {
	if log == nil {
		log = NewEventLog(io.Discard)
	}
	extProc, err := NewExtProcGRPCServer(policy, secrets, log)
	if err != nil {
		return err
	}
	server := grpc.NewServer()
	RegisterExternalProcessorServer(server, extProc)
	if ca != nil {
		secretv3.RegisterSecretDiscoveryServiceServer(server, NewSDSServer(ca, log))
		log.Record("airlock-proxy-worker envoy SDS enabled")
	}
	return server.Serve(listener)
}

type SDSServer struct {
	secretv3.UnimplementedSecretDiscoveryServiceServer
	ca  *CertificateAuthority
	log *EventLog
}

func NewSDSServer(ca *CertificateAuthority, log *EventLog) *SDSServer {
	if log == nil {
		log = NewEventLog(io.Discard)
	}
	return &SDSServer{ca: ca, log: log}
}

func (s *SDSServer) FetchSecrets(_ context.Context, request *discoveryv3.DiscoveryRequest) (*discoveryv3.DiscoveryResponse, error) {
	response, err := s.responseFor(request)
	if err != nil {
		return nil, err
	}
	s.log.Record(fmt.Sprintf("airlock-proxy-worker sds fetch resources=%s", strings.Join(request.GetResourceNames(), ",")))
	return response, nil
}

func (s *SDSServer) StreamSecrets(stream secretv3.SecretDiscoveryService_StreamSecretsServer) error {
	var lastResources []string
	for {
		request, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if request.GetResponseNonce() != "" {
			if request.GetErrorDetail() != nil {
				s.log.Record(fmt.Sprintf("airlock-proxy-worker sds nack resources=%s error=%s", strings.Join(request.GetResourceNames(), ","), request.GetErrorDetail().GetMessage()))
			}
			continue
		}
		if len(request.GetResourceNames()) > 0 {
			lastResources = append([]string(nil), request.GetResourceNames()...)
		} else if len(lastResources) > 0 {
			request.ResourceNames = append([]string(nil), lastResources...)
		}
		response, err := s.responseFor(request)
		if err != nil {
			return err
		}
		s.log.Record(fmt.Sprintf("airlock-proxy-worker sds stream resources=%s", strings.Join(request.GetResourceNames(), ",")))
		if err := stream.Send(response); err != nil {
			return err
		}
	}
}

func (s *SDSServer) responseFor(request *discoveryv3.DiscoveryRequest) (*discoveryv3.DiscoveryResponse, error) {
	resources := request.GetResourceNames()
	if len(resources) == 0 {
		return &discoveryv3.DiscoveryResponse{
			VersionInfo: time.Now().UTC().Format(time.RFC3339Nano),
			TypeUrl:     envoySecretTypeURL,
			Nonce:       fmt.Sprintf("%d", time.Now().UnixNano()),
		}, nil
	}
	secrets := make([]*anypb.Any, 0, len(resources))
	for _, name := range resources {
		secret, err := s.secretFor(strings.TrimSpace(name))
		if err != nil {
			return nil, err
		}
		packed, err := anypb.New(secret)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, packed)
	}
	now := time.Now()
	return &discoveryv3.DiscoveryResponse{
		VersionInfo: now.UTC().Format(time.RFC3339Nano),
		Resources:   secrets,
		TypeUrl:     envoySecretTypeURL,
		Nonce:       fmt.Sprintf("%d", now.UnixNano()),
	}, nil
}

func (s *SDSServer) secretFor(name string) (*tlsv3.Secret, error) {
	if name == "" {
		return nil, fmt.Errorf("SDS resource name is required")
	}
	certPEM, keyPEM, err := s.ca.LeafCertificatePEM(name)
	if err != nil {
		return nil, err
	}
	return &tlsv3.Secret{
		Name: name,
		Type: &tlsv3.Secret_TlsCertificate{
			TlsCertificate: &tlsv3.TlsCertificate{
				CertificateChain: inlineBytes(certPEM),
				PrivateKey:       inlineBytes(keyPEM),
			},
		},
	}, nil
}

func inlineBytes(value []byte) *corev3.DataSource {
	return &corev3.DataSource{Specifier: &corev3.DataSource_InlineBytes{InlineBytes: value}}
}
