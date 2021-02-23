package apkverifier_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/avast/apkverifier/signingblock"

	"github.com/avast/apkverifier"

	"github.com/avast/apkverifier/apilevel"
)

// From https://android.googlesource.com/platform/tools/apksig 907b962a6702ca25a28ed54b14964b5b713aeedb

const (
	RSA_2048_CERT_SHA256_DIGEST   = "fb5dbd3c669af9fc236c6991e6387b7f11ff0590997f22d0f5c74ff40e04fca8"
	RSA_2048_2_CERT_SHA256_DIGEST = "681b0e56a796350c08647352a4db800cc44b2adc8f4c72fa350bd05d4d50264d"
	RSA_2048_3_CERT_SHA256_DIGEST = "bb77a72efc60e66501ab75953af735874f82cfe52a70d035186a01b3482180f3"
	EC_P256_CERT_SHA256_DIGEST    = "6a8b96e278e58f62cfe3584022cec1d0527fcb85a9e5d2e1694eb0405be5b599"
	EC_P256_2_CERT_SHA256_DIGEST  = "d78405f761ff6236cc9b570347a570aba0c62a129a3ac30c831c64d09ad95469"
)

func TestSourceStampCorrectSignature(t *testing.T) {
	stampAssertVerifiedSdk(t, "valid-stamp.apk", apilevel.V_AnyMin, apilevel.V_AnyMax)
	stampAssertVerifiedSdk(t, "valid-stamp.apk", apilevel.V4_3_JellyBean, apilevel.V4_3_JellyBean)
	stampAssertVerifiedSdk(t, "valid-stamp.apk", apilevel.V7_0_Nougat, apilevel.V7_0_Nougat)
	stampAssertVerifiedSdk(t, "valid-stamp.apk", apilevel.V9_0_Pie, apilevel.V9_0_Pie)
}

func TestSourceStampRotatedV3KeySigningCertDigestMatch(t *testing.T) {
	r := stampAssertVerifiedSdk(t, "v1v2v3-rotated-v3-key-valid-stamp.apk", apilevel.V4_3_JellyBean, apilevel.V4_3_JellyBean)
	stampAssertCert(t, r, 1, EC_P256_CERT_SHA256_DIGEST)

	r = stampAssertVerifiedSdk(t, "v1v2v3-rotated-v3-key-valid-stamp.apk", apilevel.V7_0_Nougat, apilevel.V7_0_Nougat)
	stampAssertCert(t, r, 2, EC_P256_CERT_SHA256_DIGEST)

	r = stampAssertVerifiedSdk(t, "v1v2v3-rotated-v3-key-valid-stamp.apk", apilevel.V9_0_Pie, apilevel.V9_0_Pie)
	stampAssertCert(t, r, 3, EC_P256_2_CERT_SHA256_DIGEST)
}

func TestSourceStampSignatureMissing(t *testing.T) {
	stampAssertFailureSdk(t, "stamp-without-block.apk", apilevel.V_AnyMin, apilevel.V9_0_Pie,
		"SourceStampV2 block is missing")
}

func TestSourceStampCertificateMismatch(t *testing.T) {
	r := stampAssertFailureSdk(t, "stamp-certificate-mismatch.apk", apilevel.V_AnyMin, apilevel.V_AnyMax, anyErrorString)
	var merr *signingblock.SourceStampCertMismatchError
	if err := r.SigningBlockResult.SourceStamp.Errors[0]; !errors.As(err, &merr) {
		t.Fatalf("Expected SourceStampCertMismatchError from stamp-certificate-mismatch.apk, got %T: %v", err, err)
	}
}

func TestSourceStampV1OnlySignatureValidStamp(t *testing.T) {
	r := stampAssertVerifiedSdk(t, "v1-only-with-stamp.apk", apilevel.V_AnyMin, apilevel.V_AnyMax)
	stampAssertCert(t, r, 1, EC_P256_CERT_SHA256_DIGEST)

	r = stampAssertVerifiedSdk(t, "v1-only-with-stamp.apk", apilevel.V9_0_Pie, apilevel.V9_0_Pie)
	stampAssertCert(t, r, 1, EC_P256_CERT_SHA256_DIGEST)

	r = stampAssertVerifiedSdk(t, "v1-only-with-stamp.apk", apilevel.V7_0_Nougat, apilevel.V7_0_Nougat)
	stampAssertCert(t, r, 1, EC_P256_CERT_SHA256_DIGEST)
}

func TestSourceStampV2OnlySignatureValidStamp(t *testing.T) {
	r := stampAssertVerifiedSdk(t, "v2-only-with-stamp.apk", apilevel.V7_0_Nougat, apilevel.V7_0_Nougat)
	stampAssertCert(t, r, 2, EC_P256_CERT_SHA256_DIGEST)

	r = stampAssertVerifiedSdk(t, "v2-only-with-stamp.apk", apilevel.V9_0_Pie, apilevel.V9_0_Pie)
	stampAssertCert(t, r, 2, EC_P256_CERT_SHA256_DIGEST)
}

func TestSourceStampV3OnlySignatureValidStamp(t *testing.T) {
	r := stampAssertVerifiedSdk(t, "v3-only-with-stamp.apk", apilevel.V9_0_Pie, apilevel.V9_0_Pie)
	stampAssertCert(t, r, 3, EC_P256_CERT_SHA256_DIGEST)
}

func TestSourceStampApkHashMismatchV1Scheme(t *testing.T) {
	stampAssertFailureSdk(t, "stamp-apk-hash-mismatch-v1.apk", apilevel.V_AnyMin, apilevel.V6_0_Marshmallow,
		"failed to verify signature")
}

func TestSourceStampApkHashMismatchV2Scheme(t *testing.T) {
	stampAssertFailureSdk(t, "stamp-apk-hash-mismatch-v2.apk", apilevel.V_AnyMin, apilevel.V7_0_Nougat,
		"failed to verify signature")
}

func TestSourceStampApkHashMismatchV3Scheme(t *testing.T) {
	stampAssertFailureSdk(t, "stamp-apk-hash-mismatch-v3.apk", apilevel.V_AnyMin, apilevel.V9_0_Pie,
		"failed to verify signature")
}

func TestSourceStampMalformedSignature(t *testing.T) {
	stampAssertFailureSdk(t, "stamp-malformed-signature.apk", apilevel.V_AnyMin, apilevel.V_AnyMax,
		"failed to parse top-level block")
}

func TestSourceStampExpectedDigestMatchesActual(t *testing.T) {
	r := stampAssertVerifiedSdk(t, "v3-only-with-stamp.apk", apilevel.V9_0_Pie, apilevel.V9_0_Pie)
	stampAssertStampCertHash(t, r, RSA_2048_CERT_SHA256_DIGEST)
}

func TestSourceStampExpectedDigestMismatch(t *testing.T) {
	r := stampAssertVerifiedSdk(t, "v3-only-with-stamp.apk", apilevel.V9_0_Pie, apilevel.V9_0_Pie)
	stampAssertCertHashMismatch(t, r, EC_P256_CERT_SHA256_DIGEST)
}

func TestSourceStampNoStampCertDigestNorSignatureBlock(t *testing.T) {
	r := assertVerified(t, "original.apk")
	if r.SigningBlockResult != nil && r.SigningBlockResult.SourceStamp != nil {
		t.Fatalf("Source stamp present, expected missing")
	}
}

func TestSourceStampValidStampLineage(t *testing.T) {
	r := stampAssertVerifiedSdk(t, "stamp-lineage-valid.apk", apilevel.V_AnyMin, apilevel.V_AnyMax)
	stampAssertCertsInLineage(t, r, RSA_2048_CERT_SHA256_DIGEST, RSA_2048_2_CERT_SHA256_DIGEST)
}

func TestSourceStampInvalidStampLineage(t *testing.T) {
	stampAssertFailureSdk(t, "stamp-lineage-invalid.apk", apilevel.V_AnyMin, apilevel.V_AnyMax,
		"lineage certificate mismatch")
}

func TestSourceStampMultipleSignersInLineage(t *testing.T) {
	r := stampAssertVerifiedSdk(t, "stamp-lineage-with-3-signers.apk", apilevel.V4_3_JellyBean, apilevel.V9_0_Pie)
	stampAssertCertsInLineage(t, r, RSA_2048_CERT_SHA256_DIGEST, RSA_2048_2_CERT_SHA256_DIGEST, RSA_2048_3_CERT_SHA256_DIGEST)
}

func TestSourceStampNoSignersInLineageReturnsEmptyLineage(t *testing.T) {
	r := stampAssertVerifiedSdk(t, "valid-stamp.apk", apilevel.V4_3_JellyBean, apilevel.V9_0_Pie)
	stampAssertCertsInLineage(t, r)
}

func TestSourceStampNoApkSignatureSucceeds(t *testing.T) {
	r := assertVerificationFailureSdk(t, "stamp-without-apk-signature.apk", apilevel.V4_3_JellyBean, apilevel.V9_0_Pie,
		"No signatures")

	if r.SigningBlockResult == nil || r.SigningBlockResult.SourceStamp == nil {
		t.Fatal("No Source stamp extracted")
	}
	if st := r.SigningBlockResult.SourceStamp; len(st.Errors) != 0 {
		t.Fatal("Got source stamp errors", st.Errors)
	}
}

func stampAssertVerifiedSdk(t *testing.T, name string, minSdkVersion, maxSdkVersion int32) apkverifier.Result {
	res := assertVerifiedSdk(t, name, minSdkVersion, maxSdkVersion)
	if res.SigningBlockResult == nil {
		t.Fatal("No signing block result in", name, formatResult(t, res))
	}

	st := res.SigningBlockResult.SourceStamp
	if st == nil {
		t.Fatal("No source stamp result in", name, formatResult(t, res))
	}

	if len(st.Errors) != 0 {
		t.Fatal("Source stamp contains errors", name, minSdkVersion, maxSdkVersion, st.Errors)
	}
	return res
}

func stampAssertFailureSdk(t *testing.T, name string, minSdkVersion, maxSdkVersion int32, expectedError string) apkverifier.Result {
	res := assertVerifiedSdk(t, name, minSdkVersion, maxSdkVersion)
	if res.SigningBlockResult == nil {
		t.Fatal("No signing block result in", name, formatResult(t, res))
	}

	st := res.SigningBlockResult.SourceStamp
	if st == nil {
		t.Fatal("No source stamp result in", name, formatResult(t, res))
	}

	if len(st.Errors) == 0 {
		t.Fatal("Source stamp does not have any errors", name, minSdkVersion, maxSdkVersion)
	}

	if expectedError == anyErrorString {
		return res
	}

	for _, e := range st.Errors {
		if strings.Contains(e.Error(), expectedError) {
			return res
		}
	}

	t.Fatalf("%s was supposed to fail verification with '%s', but returned error %v instead\n%s",
		name, expectedError, st.Errors, formatResult(t, res))
	return res
}

func stampAssertCert(t *testing.T, r apkverifier.Result, expectedScheme int, expectedCertHash string) {
	if len(r.SignerCerts) != 1 || len(r.SignerCerts[0]) != 1 {
		t.Fatal("Invalid certs array, stampAssertCert support only single cert", r.SignerCerts)
	}

	if r.SigningSchemeId != expectedScheme {
		t.Fatalf("Got scheme %d, expected %d %s", r.SigningSchemeId, expectedScheme, formatResult(t, r))
	}

	hash := sha256.Sum256(r.SignerCerts[0][0].Raw)
	hashHex := hex.EncodeToString(hash[:])
	if hashHex != expectedCertHash {
		t.Fatalf("Got cert hash %s, expected %s %s", hashHex, expectedCertHash, formatResult(t, r))
	}
}

func stampAssertStampCertHash(t *testing.T, r apkverifier.Result, expectedCertHash string) {
	hashRaw := sha256.Sum256(r.SigningBlockResult.SourceStamp.Cert.Raw)
	hashHex := hex.EncodeToString(hashRaw[:])
	if hashHex != expectedCertHash {
		t.Fatalf("Got cert hash %s, expected %s %s", hashHex, expectedCertHash, formatResult(t, r))
	}
}

func stampAssertCertHashMismatch(t *testing.T, r apkverifier.Result, expectedCertHash string) {
	hashRaw := sha256.Sum256(r.SigningBlockResult.SourceStamp.Cert.Raw)
	hashHex := hex.EncodeToString(hashRaw[:])
	if hashHex == expectedCertHash {
		t.Fatalf("Got cert hash match %s: %s", hashHex, formatResult(t, r))
	}
}

func stampAssertCertsInLineage(t *testing.T, r apkverifier.Result, expectedCerts ...string) {
	lineage := r.SigningBlockResult.SourceStamp.Lineage
	if len(lineage) != len(expectedCerts) {
		t.Fatal("Unexpected # of lineage certs", len(lineage), len(expectedCerts), lineage)
	}

	for i := range expectedCerts {
		hashRaw := sha256.Sum256(lineage[i].Cert.Raw)
		hashHex := hex.EncodeToString(hashRaw[:])
		if expectedCerts[i] != hashHex {
			t.Fatal("Stamp lineage mismatch at signer", i, expectedCerts[i], hashHex, lineage)
		}
	}
}
