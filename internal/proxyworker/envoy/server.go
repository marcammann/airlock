package envoy

import (
	"context"
	"io"
	"net"

	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/marcammann/airlock/internal/proxyworker/builtin"
	"github.com/marcammann/airlock/internal/proxyworker/egress"
	"github.com/marcammann/airlock/internal/proxyworker/sds"
	workersecrets "github.com/marcammann/airlock/internal/proxyworker/secrets"
	workertel "github.com/marcammann/airlock/internal/proxyworker/telemetry"
	"google.golang.org/grpc"
)

// Server combines Envoy ext_proc and optional SDS services on one gRPC server.
type Server struct {
	grpc    *grpc.Server
	extProc *ExtProcGRPCServer
}

// NewServer creates an Envoy integration server for the supplied policy.
func NewServer(policy egress.CompiledPolicy, secrets workersecrets.SecretProvider, log *workertel.EventLog, ca *builtin.CertificateAuthority) (*Server, error) {
	if log == nil {
		log = workertel.NewEventLog(io.Discard)
	}
	extProc, err := NewExtProcGRPCServer(policy, secrets, log)
	if err != nil {
		return nil, err
	}
	server := NewEnvoyGRPCServer()
	RegisterExternalProcessorServer(server, extProc)
	if ca != nil {
		secretv3.RegisterSecretDiscoveryServiceServer(server, sds.NewServer(ca, log))
		log.Record(workertel.DecisionNone, "airlock-proxy-worker envoy SDS enabled")
	}
	return &Server{grpc: server, extProc: extProc}, nil
}

// UpdatePolicy swaps the policy used by future ext_proc requests.
func (s *Server) UpdatePolicy(policy egress.CompiledPolicy) {
	s.extProc.UpdatePolicy(policy)
}

// Serve starts the Envoy gRPC services until the context is canceled.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	return ServeGRPC(ctx, s.grpc, listener)
}
