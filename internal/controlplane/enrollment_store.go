package controlplane

import controlenrollment "github.com/marcammann/airlock/internal/controlplane/enrollment"

// EnrollmentStore stores one-time enrollment tokens.
type EnrollmentStore = controlenrollment.Store

// EnrollmentStoreOptions configures enrollment token lifetimes.
type EnrollmentStoreOptions = controlenrollment.StoreOptions

// NewEnrollmentStore creates an in-memory enrollment token store.
func NewEnrollmentStore(opts EnrollmentStoreOptions) *EnrollmentStore {
	return controlenrollment.NewStore(opts)
}
