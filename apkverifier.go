// Package apkverifier does APK signature verification.
// It should support all algorithms and schemes supported Android, including scheme v2 verification
// and checks for downgrade attack to v1.
package apkverifier

import (
	"github.com/avast/apkparser"
	"crypto/x509"
)

// Contains result of Apk verification
type Result struct {
	UsingSchemeV2 bool
	SignerCerts   [][]*x509.Certificate
}

// Verify the application signature. If err is nil, the signature is correct,
// otherwise it is not and res may or may not contain extracted certificates,
// depending on how the signature verification failed.
// Path is required, pass optionalZip if you have the ZipReader already opened and want to reuse it.
// This method will not close it.
func Verify(path string, optionalZip *apkparser.ZipReader) (res Result, err error) {
	res.SignerCerts, err = verifySchemeV2(path)
	if err == nil || !isSchemeV2NotFoundError(err) {
		res.UsingSchemeV2 = true
		return
	}

	if optionalZip == nil {
		optionalZip, err = apkparser.OpenZip(path)
		if err != nil {
			return Result{}, err
		}
		defer optionalZip.Close()
	}

	res.SignerCerts, err = verifySchemeV1(optionalZip)
	return
}
