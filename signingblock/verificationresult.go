package signingblock

import (
	"crypto/x509"
	"fmt"
)

type VerificationResult struct {
	Certs [][]*x509.Certificate
	SchemeId int
	SigningLineage *V3SigningLineage

	Warnings []string
	Errors []error
}

type certAdder struct {
	Certs []*x509.Certificate

	res *VerificationResult
}

func (r *VerificationResult) addWarning(format string, args ...interface{}) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}

func (r *VerificationResult) addError(format string, args ...interface{}) {
	r.Errors = append(r.Errors, fmt.Errorf(format, args...))
}

func (r *VerificationResult) ContainsErrors() bool {
	return len(r.Errors) != 0
}

func (r *VerificationResult) GetLastError() error {
	if l := len(r.Errors); l != 0 {
		return r.Errors[l-1]
	}
	return nil
}

func (r *VerificationResult) getCertAdder() certAdder {
	return certAdder{
		res: r,
	}
}

func (a *certAdder) append(cert *x509.Certificate) {
	a.Certs = append(a.Certs, cert)
	if len(a.Certs) == 1 {
		a.res.Certs = append(a.res.Certs, a.Certs)
	} else {
		idx := len(a.res.Certs)-1
		a.res.Certs[idx] = a.Certs
	}
}

