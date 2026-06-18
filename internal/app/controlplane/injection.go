package controlplane

import "github.com/marcammann/airlock/internal/controlplane"

func injectionOptionsFromConfig(config controlPlaneConfig) controlplane.InjectionOptions {
	return controlplane.InjectionOptions{
		TrustDomain:          config.SPIFFETrustDomain,
		ProxyWorkerImage:     config.InjectProxyWorkerImage,
		EnvoyImage:           config.InjectEnvoyImage,
		ControlPlaneURL:      config.InjectControlPlaneURL,
		ControlPlaneServerID: config.InjectControlPlaneServerID,
		SPIFFESocket:         config.SPIFFESocket,
		UpstreamHost:         config.InjectUpstreamHost,
		UpstreamPort:         config.InjectUpstreamPort,
	}
}
