package controlplane

import (
	controlenrollment "github.com/marcammann/airlock/internal/controlplane/enrollment"
)

// EnrollmentAuthorizer authorizes enrollment token creation.
type EnrollmentAuthorizer = controlenrollment.Authorizer

// EnrollmentGrant permits selected principals to enroll selected workloads.
type EnrollmentGrant = controlenrollment.Grant

// EnrollmentWorkloadSelector selects workloads in enrollment grants.
type EnrollmentWorkloadSelector = controlenrollment.WorkloadSelector

// NewEnrollmentAuthorizer creates an enrollment authorizer from grants.
func NewEnrollmentAuthorizer(grants []EnrollmentGrant) *EnrollmentAuthorizer {
	return controlenrollment.NewAuthorizer(grants)
}
