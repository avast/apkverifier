// Package apkverifier does APK signature verification.
// It should support all algorithms and schemes supported Android, including scheme v2 verification
// and checks for downgrade attack to v1.
package apkverifier

import (
	"crypto/x509"
	"errors"
	"github.com/avast/apkparser"
)

// Contains result of Apk verification
type Result struct {
	UsingSchemeV2 bool
	SignerCerts   [][]*x509.Certificate
}

var ErrMixedDexApkFile = errors.New("This file is both DEX and ZIP archive! Exploit?")

const (
	dexHeaderMagic uint32 = 0xa786564 // "dex\n", littleendinan
)

// Verify the application signature. If err is nil, the signature is correct,
// otherwise it is not and res may or may not contain extracted certificates,
// depending on how the signature verification failed.
// Path is required, pass optionalZip if you have the ZipReader already opened and want to reuse it.
// This method will not close it.
func Verify(path string, optionalZip *apkparser.ZipReader) (res Result, err error) {
	var fileMagic uint32
	res.SignerCerts, fileMagic, err = verifySchemeV2(path)
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

	if err == nil && fileMagic == dexHeaderMagic {
		err = ErrMixedDexApkFile
	}

	return
}
