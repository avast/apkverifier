package apkverifier

import (
	"github.com/avast/apkparser"
	"crypto/x509"
)

type Result struct {
	UsingSchemeV2 bool
	SignerCerts   [][]*x509.Certificate
}

func Verify(path string, optionalZip *apkparser.ZipReader) (res Result, err error) {
	res.SignerCerts, err = verifySchemeV2(path)
	if err == nil || !isSchemeV2NotFoundError(err) {
		res.UsingSchemeV2 = true
		return
	}

	if optionalZip == nil {
		optionalZip, err := apkparser.OpenZip(path)
		if err != nil {
			return Result{}, err
		}
		defer optionalZip.Close()
	}

	res.SignerCerts, err = verifySchemeV1(optionalZip)
	return
}
