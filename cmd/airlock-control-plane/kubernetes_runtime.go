package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	airlockv1 "github.com/marcammann/airlock/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	ctrlmanager "sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"
)

type kubernetesControllerRuntime struct {
	Manager      ctrlmanager.Manager
	DirectClient ctrlclient.Client
}

type kubernetesWebhookConfig struct {
	Listen       string
	CertFile     string
	KeyFile      string
	ClientCAFile string
}

func runKubernetesManager(ctx context.Context, manager ctrlmanager.Manager, stop func()) {
	if err := manager.Start(ctx); err != nil && ctx.Err() == nil {
		slog.Error("kubernetes manager stopped", "error", err)
		stop()
	}
}

func newKubernetesDirectClient() (ctrlclient.Client, error) {
	scheme, err := newKubernetesScheme()
	if err != nil {
		return nil, err
	}
	restConfig, err := ctrlconfig.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("load Kubernetes config: %w", err)
	}
	directClient, err := ctrlclient.New(restConfig, ctrlclient.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	return directClient, nil
}

func newKubernetesControllerRuntime(namespace string, leaderElection bool, syncPeriod time.Duration, webhookConfig kubernetesWebhookConfig) (*kubernetesControllerRuntime, error) {
	scheme, err := newKubernetesScheme()
	if err != nil {
		return nil, err
	}
	restConfig, err := ctrlconfig.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("load Kubernetes config: %w", err)
	}
	directClient, err := ctrlclient.New(restConfig, ctrlclient.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	webhookServer, err := newKubernetesWebhookServer(webhookConfig)
	if err != nil {
		return nil, err
	}
	manager, err := ctrlmanager.New(restConfig, newKubernetesManagerOptions(scheme, namespace, leaderElection, syncPeriod, webhookServer))
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes manager: %w", err)
	}
	return &kubernetesControllerRuntime{
		Manager:      manager,
		DirectClient: directClient,
	}, nil
}

func newKubernetesScheme() (*runtime.Scheme, error) {
	scheme := runtime.NewScheme()
	if err := airlockv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("register Airlock Kubernetes API scheme: %w", err)
	}
	return scheme, nil
}

func newKubernetesManagerOptions(scheme *runtime.Scheme, namespace string, leaderElection bool, syncPeriod time.Duration, webhookServer ctrlwebhook.Server) ctrlmanager.Options {
	if syncPeriod <= 0 {
		syncPeriod = 10 * time.Second
	}
	options := ctrlmanager.Options{
		Scheme:                  scheme,
		LeaderElection:          leaderElection,
		LeaderElectionID:        "airlock-control-plane.airlock.dev",
		LeaderElectionNamespace: strings.TrimSpace(namespace),
		Metrics:                 metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress:  "0",
		Cache: ctrlcache.Options{
			SyncPeriod: &syncPeriod,
		},
	}
	if webhookServer != nil {
		options.WebhookServer = webhookServer
	}
	if namespace = strings.TrimSpace(namespace); namespace != "" {
		options.Cache.DefaultNamespaces = map[string]ctrlcache.Config{namespace: {}}
	}
	return options
}

func newKubernetesWebhookServer(config kubernetesWebhookConfig) (ctrlwebhook.Server, error) {
	listen := strings.TrimSpace(config.Listen)
	if listen == "" {
		return nil, nil
	}
	if strings.TrimSpace(config.CertFile) == "" || strings.TrimSpace(config.KeyFile) == "" {
		return nil, fmt.Errorf("--webhook-cert-file and --webhook-key-file are required when --webhook-listen is set")
	}
	host, port, err := splitKubernetesWebhookListenAddress(listen)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load webhook TLS certificate: %w", err)
	}
	var clientCAs *x509.CertPool
	if strings.TrimSpace(config.ClientCAFile) != "" {
		pool, err := loadCertPool(config.ClientCAFile)
		if err != nil {
			return nil, err
		}
		clientCAs = pool
	}
	return ctrlwebhook.NewServer(ctrlwebhook.Options{
		Host: host,
		Port: port,
		TLSOpts: []func(*tls.Config){
			func(tlsConfig *tls.Config) {
				tlsConfig.MinVersion = tls.VersionTLS12
				tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					return &certificate, nil
				}
				if clientCAs != nil {
					tlsConfig.ClientCAs = clientCAs
					tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
				}
			},
		},
	}), nil
}

func splitKubernetesWebhookListenAddress(listen string) (string, int, error) {
	host, portText, err := net.SplitHostPort(listen)
	if err != nil {
		return "", 0, fmt.Errorf("parse --webhook-listen: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 {
		return "", 0, fmt.Errorf("--webhook-listen port must be a positive integer")
	}
	return host, port, nil
}
