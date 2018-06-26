// Package apkverifier does APK signature verification.
// It should support all algorithms and schemes supported Android, including scheme v2 verification
// and checks for downgrade attack to v1.
package apkverifier

import (
	"crypto/x509"
	"errors"
	"github.com/avast/apkparser"
	"github.com/avast/apkverifier/signingblock"
)

// Contains result of Apk verification
type Result struct {
	SigningSchemeId    int
	SignerCerts        [][]*x509.Certificate
	SigningBlockResult *signingblock.VerificationResult
}

// Returned from the Verify method if the file starts with the DEX magic value,
// but otherwise looks like a properly signed APK.
//
// This detect 'Janus' Android vulnerability where a DEX is prepended to a valid,
// signed APK file. The signature verification passes because with v1 scheme,
// only the APK portion of the file is checked, but Android then loads the prepended,
// unsigned DEX file instead of the one from APK.
// https://www.guardsquare.com/en/blog/new-android-vulnerability-allows-attackers-modify-apps-without-affecting-their-signatures
//
// If this error is returned, the signature is otherwise valid (the err would be nil
// had it not have the DEX file prepended).
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
	res.SigningBlockResult, fileMagic, err = signingblock.VerifySigningBlock(path)
	if err == nil || !signingblock.IsSigningBlockNotFoundError(err) {
		res.SignerCerts = res.SigningBlockResult.Certs
		res.SigningSchemeId = res.SigningBlockResult.SchemeId
		return
	} else {
		res.SigningSchemeId = 1
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
