package proxyworker

import (
	"fmt"
	"strings"
)

type ExtProcDecision struct {
	Continue  bool
	Mutations []Header
	Deny      bool
	Status    uint16
	Body      string
	Details   string
}

func (d ExtProcDecision) Equal(other ExtProcDecision) bool {
	if d.Continue != other.Continue || d.Deny != other.Deny || d.Status != other.Status || d.Body != other.Body || d.Details != other.Details {
		return false
	}
	if len(d.Mutations) != len(other.Mutations) {
		return false
	}
	for i := range d.Mutations {
		if d.Mutations[i] != other.Mutations[i] {
			return false
		}
	}
	return true
}

func EvaluateExtProcHeaders(policy CompiledPolicy, requestHeaders []Header, secrets SecretProvider, log *EventLog) (ExtProcDecision, error) {
	if log == nil {
		log = NewEventLog(nil)
	}
	method, ok := headerValue(requestHeaders, ":method")
	if !ok {
		method = "UNKNOWN"
	}
	destination, err := destinationFromHeaders(requestHeaders, method)
	if err != nil {
		return ExtProcDecision{}, err
	}
	rule := FindEgressRule(policy, destination)
	if rule == nil {
		log.Record(fmt.Sprintf(
			"denied ext_proc request policy=%s policy_version=%s method=%s destination=%s:%d",
			policy.PolicyName,
			policy.Version,
			method,
			destination.Host,
			destination.Port,
		))
		return ExtProcDecision{Deny: true, Status: 403, Body: "egress denied", Details: "airlock_egress_denied"}, nil
	}
	if strings.EqualFold(method, "CONNECT") {
		log.Record(fmt.Sprintf(
			"allowed ext_proc CONNECT policy=%s policy_version=%s rule=%s destination=%s:%d",
			policy.PolicyName,
			policy.Version,
			rule.Name,
			destination.Host,
			destination.Port,
		))
		return ExtProcDecision{Continue: true}, nil
	}

	var redactor Redactor
	rewritten := append([]Header(nil), requestHeaders...)
	if err := ApplyRewrites(&rewritten, rule.Rewrites, secrets, &redactor); err != nil {
		log.Record(fmt.Sprintf(
			"denied ext_proc request policy=%s policy_version=%s rule=%s method=%s destination=%s:%d dependency=secret error=%v",
			policy.PolicyName,
			policy.Version,
			rule.Name,
			method,
			destination.Host,
			destination.Port,
			err,
		))
		return ExtProcDecision{}, err
	}
	var mutations []Header
	for _, rewrite := range rule.Rewrites {
		if value, ok := headerValue(rewritten, rewrite.Name); ok {
			mutations = append(mutations, Header{Name: rewrite.Name, Value: value})
		}
	}
	log.Record(redactor.Redact(fmt.Sprintf(
		"allowed ext_proc request policy=%s policy_version=%s rule=%s method=%s destination=%s:%d mutations=%+v",
		policy.PolicyName,
		policy.Version,
		rule.Name,
		method,
		destination.Host,
		destination.Port,
		mutations,
	)))
	return ExtProcDecision{Continue: true, Mutations: mutations}, nil
}
