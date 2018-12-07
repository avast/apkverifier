// Package apkverifier does APK signature verification.
// It should support all algorithms and schemes supported Android, including scheme v2 verification
// and checks for downgrade attack to v1.
package apkverifier

import (
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/avast/apkparser"
	"github.com/avast/apkverifier/signingblock"
	"io"
	"math"
	"strconv"
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

// Calls VerifyWithSdkVersion with sdk versions <-1;Math.MaxInt32>
func Verify(path string, optionalZip *apkparser.ZipReader) (res Result, err error) {
	return VerifyWithSdkVersion(path, optionalZip, -1, math.MaxInt32)
}

// Verify the application signature. If err is nil, the signature is correct,
// otherwise it is not and res may or may not contain extracted certificates,
// depending on how the signature verification failed.
// Path is required, pass optionalZip if you have the ZipReader already opened and want to reuse it.
// This method will not close it.
// minSdkVersion and maxSdkVersion means the apk has to successfuly verify on real devices with sdk version
// inside the <minSdkVersion;maxSdkVersion> interval.
// minSdkVersion == -1 means it will obtain the minSdkVersion from AndroidManifest.
func VerifyWithSdkVersion(path string, optionalZip *apkparser.ZipReader, minSdkVersion, maxSdkVersion int32) (res Result, err error) {
	if optionalZip == nil {
		optionalZip, err = apkparser.OpenZip(path)
		if err != nil {
			return Result{}, err
		}
		defer optionalZip.Close()
	}

	var sandboxVersion int32
	var manifestError error
	if minSdkVersion == -1 || maxSdkVersion >= 26 {
		var manifestMinSdkVersion int32
		manifestMinSdkVersion, sandboxVersion, err = getManifestInfo(optionalZip)
		if err != nil {
			manifestError = err
		} else {
			if minSdkVersion == -1 {
				minSdkVersion = manifestMinSdkVersion
			}
		}
	}

	if minSdkVersion > maxSdkVersion {
		err = fmt.Errorf("invalid sdk version range <%d;%d>", minSdkVersion, maxSdkVersion)
		return
	}

	var fileMagic uint32
	var signingBlockError error
	res.SigningBlockResult, fileMagic, signingBlockError = signingblock.VerifySigningBlock(path, minSdkVersion, maxSdkVersion)

	if res.SigningBlockResult != nil {
		res.SignerCerts = res.SigningBlockResult.Certs
		res.SigningSchemeId = res.SigningBlockResult.SchemeId
	}

	if signingblock.IsSigningBlockNotFoundError(signingBlockError) {
		res.SigningSchemeId = 1
	} else if signingBlockError != nil {
		return res, signingBlockError
	} else if minSdkVersion >= 24 && signingBlockError == nil { // If verifying for sdk higher than 24, the app does not need v1 signature
		return res, nil
	}

	// Android O and newer requires that APKs targeting security sandbox version 2 and higher
	// are signed using APK Signature Scheme v2 or newer.
	var sandboxError error
	if maxSdkVersion >= 26 && sandboxVersion > 1 && (signingBlockError != nil || res.SigningSchemeId < 2) {
		sandboxError = fmt.Errorf("no valid signature for sandbox version %d", sandboxVersion)
	}

	var certsv1 [][]*x509.Certificate
	certsv1, err = verifySchemeV1(optionalZip, signingBlockError == nil, minSdkVersion, maxSdkVersion)
	if len(res.SignerCerts) == 0 {
		res.SignerCerts = certsv1
	}

	if sandboxError != nil {
		err = sandboxError
	} else if err == nil {
		if res.SigningSchemeId != 1 && manifestError != nil {
			err = manifestError
		} else if fileMagic == dexHeaderMagic {
			err = ErrMixedDexApkFile
		}
	}

	return
}

// Extract certs without verifying the signature.
func ExtractCerts(path string, optionalZip *apkparser.ZipReader) ([][]*x509.Certificate, error) {
	var err error
	if optionalZip == nil {
		optionalZip, err = apkparser.OpenZip(path)
		if err != nil {
			return nil, err
		}
		defer optionalZip.Close()
	}

	certs, signingBlockError := signingblock.ExtractCerts(path, -1, math.MaxInt32)
	if !signingblock.IsSigningBlockNotFoundError(signingBlockError) {
		return certs, signingBlockError
	}

	var certsv1 [][]*x509.Certificate
	certsv1, err = extractCertsSchemeV1(optionalZip, -1, math.MaxInt32)
	certs = append(certs, certsv1...)
	return certs, err
}

type sandboxVersionEncoder struct {
	minSdkVersion  int32
	sandboxVersion int32
}

func (e *sandboxVersionEncoder) EncodeToken(t xml.Token) error {
	st, ok := t.(xml.StartElement)
	if !ok {
		return nil
	}

	switch st.Name.Local {
	case "manifest":
		val, err := e.getAttrIntValue(&st, "targetSandboxVersion")
		if err == nil {
			e.sandboxVersion = val
		} else if err != io.EOF {
			return err
		}
	case "uses-sdk":
		val, err := e.getAttrIntValue(&st, "minSdkVersion")
		if err == nil {
			e.minSdkVersion = val
		} else if err != io.EOF {
			return err
		}
		return apkparser.ErrEndParsing
	}
	return nil
}

func (e *sandboxVersionEncoder) Flush() error {
	return nil
}

func (e *sandboxVersionEncoder) getAttrIntValue(st *xml.StartElement, name string) (int32, error) {
	for _, attr := range st.Attr {
		if attr.Name.Local == name {
			val, err := strconv.ParseInt(attr.Value, 10, 32)
			if err != nil {
				return 0, fmt.Errorf("failed to decode %s '%s': %s", name, attr.Value, err.Error())
			}
			return int32(val), nil
		}
	}
	return 0, io.EOF
}

func getManifestInfo(zip *apkparser.ZipReader) (minSdkVersion, sandboxVersion int32, err error) {
	manifest := zip.File["AndroidManifest.xml"]
	if manifest == nil {
		return 1, 1, nil
	}

	if err = manifest.Open(); err != nil {
		err = fmt.Errorf("failed to open AndroidManifest.xml: %s", err.Error())
		return
	}
	defer manifest.Close()

	for manifest.Next() {
		enc := sandboxVersionEncoder{1, 1}
		if err = apkparser.ParseManifest(manifest, &enc, nil); err != nil {
			err = fmt.Errorf("failed to parse AndroidManifest.xml: %s", err.Error())
			return
		}
		return enc.minSdkVersion, enc.sandboxVersion, nil
	}
	return
}
