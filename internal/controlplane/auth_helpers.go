package controlplane

import (
	"net/http"

	controlauth "github.com/marcammann/airlock/internal/controlplane/auth"
	"github.com/marcammann/airlock/internal/telemetry"
)

func (s *Server) authorized(r *http.Request, workloadIdentity string) (string, bool) {
	switch s.workerAuthMode {
	case AuthModeNone:
		if !s.insecure {
			telemetry.ObserveControlPlaneAuthFailure(string(s.workerAuthMode))
			return "", false
		}
		return "", true
	case AuthModeSPIFFE:
		id, ok := peerSPIFFEID(r)
		if !ok || id != workloadIdentity {
			telemetry.ObserveControlPlaneAuthFailure(string(s.workerAuthMode))
			return id, false
		}
		return id, true
	default:
		telemetry.ObserveControlPlaneAuthFailure(string(s.workerAuthMode))
		return "", false
	}
}

type adminAuthorization struct {
	identity  string
	ok        bool
	forbidden bool
}

func (a adminAuthorization) status() int {
	if a.forbidden {
		return http.StatusForbidden
	}
	return http.StatusUnauthorized
}

func (a adminAuthorization) outcome() string {
	if a.forbidden {
		return "forbidden"
	}
	return "unauthorized"
}

func (s *Server) authorizedAdmin(r *http.Request, permission AdminPermission) adminAuthorization {
	if s.adminAuthenticator != nil {
		principal, err := s.adminAuthenticator.AuthenticateRequest(r.Context(), r)
		if err != nil {
			telemetry.ObserveControlPlaneAuthFailure("config")
			return adminAuthorization{}
		}
		identity := principalIdentifier(principal)
		if s.adminRBAC != nil && !s.adminRBAC.Authorize(principal, permission) {
			telemetry.ObserveControlPlaneAuthFailure("config")
			return adminAuthorization{identity: identity, forbidden: true}
		}
		return adminAuthorization{identity: identity, ok: true}
	}

	switch s.adminAuthMode {
	case AuthModeNone:
		if !s.insecure {
			telemetry.ObserveControlPlaneAuthFailure(string(s.adminAuthMode))
			return adminAuthorization{}
		}
		return adminAuthorization{ok: true}
	case AuthModeSPIFFE:
		id, ok := peerSPIFFEID(r)
		if !ok {
			telemetry.ObserveControlPlaneAuthFailure(string(s.adminAuthMode))
			return adminAuthorization{}
		}
		principal := AdminPrincipal{Provider: "spiffe", Subject: id}
		if s.adminRBAC == nil {
			if s.insecure {
				return adminAuthorization{identity: id, ok: true}
			}
			telemetry.ObserveControlPlaneAuthFailure(string(s.adminAuthMode))
			return adminAuthorization{identity: id, forbidden: true}
		}
		if !s.adminRBAC.Authorize(principal, permission) {
			telemetry.ObserveControlPlaneAuthFailure(string(s.adminAuthMode))
			return adminAuthorization{identity: id, forbidden: true}
		}
		return adminAuthorization{identity: id, ok: true}
	case AuthModeOIDC:
		if s.adminOIDC == nil {
			telemetry.ObserveControlPlaneAuthFailure(string(s.adminAuthMode))
			return adminAuthorization{}
		}
		principal, err := s.adminOIDC.Authenticate(r.Context(), bearerToken(r))
		if err != nil {
			telemetry.ObserveControlPlaneAuthFailure(string(s.adminAuthMode))
			return adminAuthorization{}
		}
		identity := principalIdentifier(principal)
		if s.adminRBAC != nil && !s.adminRBAC.Authorize(principal, permission) {
			telemetry.ObserveControlPlaneAuthFailure(string(s.adminAuthMode))
			return adminAuthorization{identity: identity, forbidden: true}
		}
		return adminAuthorization{identity: identity, ok: true}
	default:
		telemetry.ObserveControlPlaneAuthFailure(string(s.adminAuthMode))
		return adminAuthorization{}
	}
}

func (s *Server) authorizedEnrollment(r *http.Request, namespace string, name string) adminAuthorization {
	if s.enrollmentAuthenticator != nil {
		principal, err := s.enrollmentAuthenticator.AuthenticateRequest(r.Context(), r)
		if err != nil {
			telemetry.ObserveControlPlaneAuthFailure("enrollment")
			return adminAuthorization{}
		}
		identity := principalIdentifier(principal)
		if s.enrollmentAuthorizer != nil && !s.enrollmentAuthorizer.Authorize(principal, AdminPermissionEnrollmentCreate, namespace, name) {
			telemetry.ObserveControlPlaneAuthFailure("enrollment")
			return adminAuthorization{identity: identity, forbidden: true}
		}
		if s.enrollmentAuthorizer == nil {
			telemetry.ObserveControlPlaneAuthFailure("enrollment")
			return adminAuthorization{identity: identity, forbidden: true}
		}
		return adminAuthorization{identity: identity, ok: true}
	}
	if s.insecure {
		return adminAuthorization{ok: true}
	}
	telemetry.ObserveControlPlaneAuthFailure("enrollment")
	return adminAuthorization{forbidden: true}
}

func bearerToken(r *http.Request) string {
	return controlauth.BearerToken(r)
}

func principalIdentifier(principal AdminPrincipal) string {
	if principal.Email != "" {
		return principal.Email
	}
	return principal.Subject
}

func peerSPIFFEID(r *http.Request) (string, bool) {
	return controlauth.PeerSPIFFEID(r)
}
