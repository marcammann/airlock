// Package sds serves Envoy Secret Discovery Service resources for proxy-worker
// TLS interception.
package sds

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	workertel "github.com/marcammann/airlock/internal/proxyworker/telemetry"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// SecretTypeURL is the Envoy xDS type URL for TLS Secret resources.
const SecretTypeURL = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"

// CertificateAuthority signs per-host leaf certificates for SDS responses.
type CertificateAuthority interface {
	LeafCertificatePEM(name string) ([]byte, []byte, error)
}

// Server implements Envoy Secret Discovery Service for MITM certificates.
type Server struct {
	secretv3.UnimplementedSecretDiscoveryServiceServer
	ca  CertificateAuthority
	log *workertel.EventLog
}

// NewServer creates an SDS server backed by a certificate authority.
func NewServer(ca CertificateAuthority, log *workertel.EventLog) *Server {
	if log == nil {
		log = workertel.NewEventLog(io.Discard)
	}
	return &Server{ca: ca, log: log}
}

// FetchSecrets handles unary SDS fetch requests.
func (s *Server) FetchSecrets(_ context.Context, request *discoveryv3.DiscoveryRequest) (*discoveryv3.DiscoveryResponse, error) {
	response, err := s.responseFor(request)
	if err != nil {
		return nil, err
	}
	s.log.Record(workertel.DecisionNone, fmt.Sprintf("airlock-proxy-worker sds fetch resources=%s", strings.Join(request.GetResourceNames(), ",")))
	return response, nil
}

// StreamSecrets handles streaming SDS discovery requests.
func (s *Server) StreamSecrets(stream secretv3.SecretDiscoveryService_StreamSecretsServer) error {
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
				s.log.Record(workertel.DecisionNone, fmt.Sprintf("airlock-proxy-worker sds nack resources=%s error=%s", strings.Join(request.GetResourceNames(), ","), request.GetErrorDetail().GetMessage()))
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
		s.log.Record(workertel.DecisionNone, fmt.Sprintf("airlock-proxy-worker sds stream resources=%s", strings.Join(request.GetResourceNames(), ",")))
		if err := stream.Send(response); err != nil {
			return err
		}
	}
}

func (s *Server) responseFor(request *discoveryv3.DiscoveryRequest) (*discoveryv3.DiscoveryResponse, error) {
	resources := request.GetResourceNames()
	if len(resources) == 0 {
		now := time.Now()
		versionInfo, err := versionInfo(nil)
		if err != nil {
			return nil, err
		}
		return &discoveryv3.DiscoveryResponse{
			VersionInfo: versionInfo,
			TypeUrl:     SecretTypeURL,
			Nonce:       fmt.Sprintf("%d", now.UnixNano()),
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
	versionInfo, err := versionInfo(secrets)
	if err != nil {
		return nil, err
	}
	return &discoveryv3.DiscoveryResponse{
		VersionInfo: versionInfo,
		Resources:   secrets,
		TypeUrl:     SecretTypeURL,
		Nonce:       fmt.Sprintf("%d", now.UnixNano()),
	}, nil
}

func versionInfo(resources []*anypb.Any) (string, error) {
	hash := sha256.New()
	marshal := proto.MarshalOptions{Deterministic: true}
	for _, resource := range resources {
		data, err := marshal.Marshal(resource)
		if err != nil {
			return "", fmt.Errorf("marshal SDS resource for version hash: %w", err)
		}
		_, _ = hash.Write(data)
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func (s *Server) secretFor(name string) (*tlsv3.Secret, error) {
	if name == "" {
		return nil, fmt.Errorf("sds resource name is required")
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
