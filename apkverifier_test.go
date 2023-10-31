package apkverifier_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avast/apkverifier/internal/x509andr"

	"github.com/avast/apkverifier"
	"github.com/avast/apkverifier/apilevel"
)

func Example() {
	res, err := apkverifier.Verify(os.Args[1], nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Verification failed: %s\n", err.Error())
	}

	fmt.Printf("Verification scheme used: v%d\n", res.SigningSchemeId)
	cert, _ := apkverifier.PickBestApkCert(res.SignerCerts)
	if cert == nil {
		fmt.Printf("No certificate found.\n")
	} else {
		fmt.Println(cert)
	}
}

// From https://android.googlesource.com/platform/tools/apksig c5b2567d87833f347cd578acc0262501c7eae423
var (
	DSA_KEY_NAMES                  = []string{"1024", "2048", "3072"}
	DSA_KEY_NAMES_1024_AND_SMALLER = []string{"1024"}
	DSA_KEY_NAMES_2048_AND_LARGER  = []string{"2048", "3072"}
	EC_KEY_NAMES                   = []string{"p256", "p384", "p521"}
	RSA_KEY_NAMES                  = []string{"1024", "2048", "3072", "4096", "8192", "16384"}
	RSA_KEY_NAMES_2048_AND_LARGER  = []string{"2048", "3072", "4096", "8192", "16384"}
)

const (
	RSA_2048_CHUNKED_SHA256_DIGEST                             = "0a457e6dd7cc8d4dde28a4dae843032de5fbe58123eedd0a31e7f958f23e1626"
	RSA_2048_CHUNKED_SHA256_DIGEST_FROM_INCORRECTLY_SIGNED_APK = "0a457e6dd7cc8d4dde28a4dae843032de5fbe58101eedd0a31e7f958f23e1626"

	FIRST_RSA_2048_SIGNER_RESOURCE_NAME  = "rsa-2048"
	SECOND_RSA_2048_SIGNER_RESOURCE_NAME = "rsa-2048_2"
	THIRD_RSA_2048_SIGNER_RESOURCE_NAME  = "rsa-2048_3"
	EC_P256_SIGNER_RESOURCE_NAME         = "ec-p256"
	EC_P256_2_SIGNER_RESOURCE_NAME       = "ec-p256_2"
)

const anyErrorString = "LiterallyAnything"

func TestOriginalAccepted(t *testing.T) {
	assertVerified(t, "original.apk")
}

func TestV1OneSignerMD5withRSAAccepted(t *testing.T) {
	// APK signed with v1 scheme only, one signer
	assertVerifiedForEach(t, "v1-only-with-rsa-pkcs1-md5-1.2.840.113549.1.1.1-%s.apk", RSA_KEY_NAMES)
	assertVerifiedForEach(t, "v1-only-with-rsa-pkcs1-md5-1.2.840.113549.1.1.4-%s.apk", RSA_KEY_NAMES)
}

func TestV1OneSignerSHA1withRSAAccepted(t *testing.T) {
	// APK signed with v1 scheme only, one signer
	assertVerifiedForEach(t, "v1-only-with-rsa-pkcs1-sha1-1.2.840.113549.1.1.1-%s.apk", RSA_KEY_NAMES)
	assertVerifiedForEach(t, "v1-only-with-rsa-pkcs1-sha1-1.2.840.113549.1.1.5-%s.apk", RSA_KEY_NAMES)
}

func TestV1OneSignerSHA224withRSAAccepted(t *testing.T) {
	// APK signed with v1 scheme only, one signer
	assertVerifiedForEach(t, "v1-only-with-rsa-pkcs1-sha224-1.2.840.113549.1.1.1-%s.apk", RSA_KEY_NAMES)
	assertVerifiedForEach(t, "v1-only-with-rsa-pkcs1-sha224-1.2.840.113549.1.1.14-%s.apk", RSA_KEY_NAMES)
}

func TestV1OneSignerSHA256withRSAAccepted(t *testing.T) {
	// APK signed with v1 scheme only, one signer
	assertVerifiedForEach(t, "v1-only-with-rsa-pkcs1-sha256-1.2.840.113549.1.1.1-%s.apk", RSA_KEY_NAMES)
	assertVerifiedForEach(t, "v1-only-with-rsa-pkcs1-sha256-1.2.840.113549.1.1.11-%s.apk", RSA_KEY_NAMES)
}

func TestV1OneSignerSHA384withRSAAccepted(t *testing.T) {
	// APK signed with v1 scheme only, one signer
	assertVerifiedForEach(t, "v1-only-with-rsa-pkcs1-sha384-1.2.840.113549.1.1.1-%s.apk", RSA_KEY_NAMES)
	assertVerifiedForEach(t, "v1-only-with-rsa-pkcs1-sha384-1.2.840.113549.1.1.12-%s.apk", RSA_KEY_NAMES)
}

func TestV1OneSignerSHA512withRSAVerifies(t *testing.T) {
	// APK signed with v1 scheme only, one signer
	assertVerifiedForEach(t, "v1-only-with-rsa-pkcs1-sha512-1.2.840.113549.1.1.1-%s.apk", RSA_KEY_NAMES)
	assertVerifiedForEach(t, "v1-only-with-rsa-pkcs1-sha512-1.2.840.113549.1.1.13-%s.apk", RSA_KEY_NAMES)
}

func TestV1OneSignerSHA1withECDSAAccepted(t *testing.T) {
	// APK signed with v1 scheme only, one signer
	assertVerifiedForEach(t, "v1-only-with-ecdsa-sha1-1.2.840.10045.2.1-%s.apk", EC_KEY_NAMES)
	assertVerifiedForEach(t, "v1-only-with-ecdsa-sha1-1.2.840.10045.4.1-%s.apk", EC_KEY_NAMES)
}

func TestV1OneSignerSHA224withECDSAAccepted(t *testing.T) {
	// APK signed with v1 scheme only, one signer
	assertVerifiedForEach(t, "v1-only-with-ecdsa-sha224-1.2.840.10045.2.1-%s.apk", EC_KEY_NAMES)
	assertVerifiedForEach(t, "v1-only-with-ecdsa-sha224-1.2.840.10045.4.3.1-%s.apk", EC_KEY_NAMES)
}

func TestV1OneSignerSHA256withECDSAAccepted(t *testing.T) {
	// APK signed with v1 scheme only, one signer
	assertVerifiedForEach(t, "v1-only-with-ecdsa-sha256-1.2.840.10045.2.1-%s.apk", EC_KEY_NAMES)
	assertVerifiedForEach(t, "v1-only-with-ecdsa-sha256-1.2.840.10045.4.3.2-%s.apk", EC_KEY_NAMES)
}

func TestV1OneSignerSHA384withECDSAAccepted(t *testing.T) {
	// APK signed with v1 scheme only, one signer
	assertVerifiedForEach(t, "v1-only-with-ecdsa-sha384-1.2.840.10045.2.1-%s.apk", EC_KEY_NAMES)
	assertVerifiedForEach(t, "v1-only-with-ecdsa-sha384-1.2.840.10045.4.3.3-%s.apk", EC_KEY_NAMES)
}

func TestV1OneSignerSHA512withECDSAAccepted(t *testing.T) {
	// APK signed with v1 scheme only, one signer
	assertVerifiedForEach(t, "v1-only-with-ecdsa-sha512-1.2.840.10045.2.1-%s.apk", EC_KEY_NAMES)
	assertVerifiedForEach(t, "v1-only-with-ecdsa-sha512-1.2.840.10045.4.3.4-%s.apk", EC_KEY_NAMES)
}

func TestV1OneSignerSHA1withDSAAccepted(t *testing.T) {
	// APK signed with v1 scheme only, one signer
	// NOTE: This test is split into two because JCA Providers shipping with OpenJDK refuse to
	// verify DSA signatures with keys too long for the SHA-1 digest.
	assertVerifiedForEach(t, "v1-only-with-dsa-sha1-1.2.840.10040.4.1-%s.apk", DSA_KEY_NAMES_1024_AND_SMALLER)
	assertVerifiedForEach(t, "v1-only-with-dsa-sha1-1.2.840.10040.4.3-%s.apk", DSA_KEY_NAMES_1024_AND_SMALLER)
}

func TestV1OneSignerSHA1withDSAAcceptedWithKeysTooLongForDigest(t *testing.T) {
	// APK signed with v1 scheme only, one signer
	assertVerifiedForEach(t, "v1-only-with-dsa-sha1-1.2.840.10040.4.1-%s.apk", DSA_KEY_NAMES_2048_AND_LARGER)
	assertVerifiedForEach(t, "v1-only-with-dsa-sha1-1.2.840.10040.4.3-%s.apk", DSA_KEY_NAMES_2048_AND_LARGER)
}

func TestV1OneSignerSHA224withDSAAccepted(t *testing.T) {
	// APK signed with v1 scheme only, one signer
	// NOTE: This test is split into two because JCA Providers shipping with OpenJDK refuse to
	// verify DSA signatures with keys too long for the SHA-224 digest.
	assertVerifiedForEach(t, "v1-only-with-dsa-sha224-1.2.840.10040.4.1-%s.apk", DSA_KEY_NAMES_1024_AND_SMALLER)
	assertVerifiedForEach(t, "v1-only-with-dsa-sha224-2.16.840.1.101.3.4.3.1-%s.apk",
		DSA_KEY_NAMES_1024_AND_SMALLER)
}

func TestV1OneSignerSHA224withDSAAcceptedWithKeysTooLongForDigest(t *testing.T) {
	// APK signed with v1 scheme only, one signer
	assertVerifiedForEach(t, "v1-only-with-dsa-sha224-1.2.840.10040.4.1-%s.apk", DSA_KEY_NAMES_2048_AND_LARGER)
	assertVerifiedForEach(t, "v1-only-with-dsa-sha224-2.16.840.1.101.3.4.3.1-%s.apk", DSA_KEY_NAMES_2048_AND_LARGER)
}

func TestV1OneSignerSHA256withDSAAccepted(t *testing.T) {
	// APK signed with v1 scheme only, one signer
	assertVerifiedForEach(t, "v1-only-with-dsa-sha256-1.2.840.10040.4.1-%s.apk", DSA_KEY_NAMES)
	assertVerifiedForEach(t, "v1-only-with-dsa-sha256-2.16.840.1.101.3.4.3.2-%s.apk", DSA_KEY_NAMES)
}

func TestV1MaxSupportedSignersAccepted(t *testing.T) {
	assertVerified(t, "v1-only-10-signers.apk")
}

func TestV1MoreThanMaxSupportedSignersRejected(t *testing.T) {
	assertVerificationFailure(t, "v1-only-11-signers.apk", "APK Signature Scheme v1 only supports a maximum")
}

func TestV2StrippedRejected(t *testing.T) {
	// APK signed with v1 and v2 schemes, but v2 signature was stripped from the file (by using
	// zipalign).
	// This should fail because the v1 signature indicates that the APK was supposed to be
	// signed with v2 scheme as well, making the platform's anti-stripping protections reject
	// the APK.
	assertVerificationFailure(t, "v2-stripped.apk", "cannot be verified using v1 scheme, downgrade attack?")
	// Similar to above, but the X-Android-APK-Signed anti-stripping header in v1 signature
	// lists unknown signature schemes in addition to APK Signature Scheme v2. Unknown schemes
	// should be ignored.
	assertVerificationFailure(t, "v2-stripped-with-ignorable-signing-schemes.apk", "cannot be verified using v1 scheme, downgrade attack?")
}

func TestV3StrippedRejected(t *testing.T) {
	// APK signed with v2 and v3 schemes, but v3 signature was stripped from the file by
	// modifying the v3 block ID to be the verity padding block ID. Without the stripping
	// protection this modification ignores the v3 signing scheme block.
	assertVerificationFailure(t, "v3-stripped.apk", "was stripped, downgrade attack")
}

func TestSignaturesIgnoredForMaxSDK(t *testing.T) {
	// The V2 signature scheme was introduced in N, and V3 was introduced in P. This test
	// verifies a max SDK of pre-P ignores the V3 signature and a max SDK of pre-N ignores both
	// the V2 and V3 signatures.
	assertVerifiedSdk(t, "v1v2v3-with-rsa-2048-lineage-3-signers.apk", apilevel.V_AnyMin, apilevel.V8_1_Oreo)
	assertVerifiedSdk(t, "v1v2v3-with-rsa-2048-lineage-3-signers.apk", apilevel.V_AnyMin, apilevel.V6_0_Marshmallow)
}

func TestV2OneSignerOneSignatureAccepted(t *testing.T) {
	// APK signed with v2 scheme only, one signer, one signature
	assertVerifiedForEachSdk(t, "v2-only-with-dsa-sha256-%s.apk", DSA_KEY_NAMES, apilevel.V7_1_Nougat, apilevel.V_AnyMax)
	assertVerifiedForEachSdk(t, "v2-only-with-ecdsa-sha256-%s.apk", EC_KEY_NAMES, apilevel.V7_1_Nougat, apilevel.V_AnyMax)
	assertVerifiedForEachSdk(t, "v2-only-with-rsa-pkcs1-sha256-%s.apk", RSA_KEY_NAMES, apilevel.V7_1_Nougat, apilevel.V_AnyMax)
	// RSA-PSS signatures tested in a separate test below
	// DSA with SHA-512 is not supported by Android platform and thus APK Signature Scheme v2
	// does not support that either
	// assertInstallSucceedsForEach("v2-only-with-dsa-sha512-%s.apk", DSA_KEY_NAMES)
	assertVerifiedForEachSdk(t, "v2-only-with-ecdsa-sha512-%s.apk", EC_KEY_NAMES, apilevel.V7_1_Nougat, apilevel.V_AnyMax)
	assertVerifiedForEachSdk(t, "v2-only-with-rsa-pkcs1-sha512-%s.apk", RSA_KEY_NAMES, apilevel.V7_1_Nougat, apilevel.V_AnyMax)
}

func TestV3OneSignerOneSignatureAccepted(t *testing.T) {
	// APK signed with v3 scheme only, one signer, one signature
	assertVerifiedForEachSdk(t, "v3-only-with-dsa-sha256-%s.apk", DSA_KEY_NAMES, apilevel.V9_0_Pie, apilevel.V_AnyMax)
	assertVerifiedForEachSdk(t, "v3-only-with-ecdsa-sha256-%s.apk", EC_KEY_NAMES, apilevel.V9_0_Pie, apilevel.V_AnyMax)
	assertVerifiedForEachSdk(t, "v3-only-with-rsa-pkcs1-sha256-%s.apk", RSA_KEY_NAMES, apilevel.V9_0_Pie, apilevel.V_AnyMax)

	assertVerifiedForEachSdk(t, "v3-only-with-ecdsa-sha512-%s.apk", EC_KEY_NAMES, apilevel.V9_0_Pie, apilevel.V_AnyMax)
	assertVerifiedForEachSdk(t, "v3-only-with-rsa-pkcs1-sha512-%s.apk", RSA_KEY_NAMES, apilevel.V9_0_Pie, apilevel.V_AnyMax)
}

func TestV2OneSignerOneRsaPssSignatureAccepted(t *testing.T) {
	// APK signed with v2 scheme only, one signer, one signature
	assertVerifiedForEachSdk(t, "v2-only-with-rsa-pss-sha256-%s.apk", RSA_KEY_NAMES, apilevel.V7_1_Nougat, apilevel.V_AnyMax)
	assertVerifiedForEachSdk(t, "v2-only-with-rsa-pss-sha512-%s.apk",
		RSA_KEY_NAMES_2048_AND_LARGER, // 1024-bit key is too short for PSS with SHA-512
		25, apilevel.V_AnyMax)
}

func TestV2SignatureDoesNotMatchSignedDataRejected(t *testing.T) {
	// APK signed with v2 scheme only, but the signature over signed-data does not verify
	// Bitflip in certificate field inside signed-data. Based on
	// v2-only-with-dsa-sha256-1024.apk.
	assertVerificationFailure(t, "v2-only-with-dsa-sha256-1024-sig-does-not-verify.apk", "verification failed")
	// Signature claims to be RSA PKCS#1 v1.5 with SHA-256, but is actually using SHA-512.
	// Based on v2-only-with-rsa-pkcs1-sha256-2048.apk.
	assertVerificationFailure(t, "v2-only-with-rsa-pkcs1-sha256-2048-sig-does-not-verify.apk", "verification error")
	// Bitflip in the ECDSA signature. Based on v2-only-with-ecdsa-sha256-p256.apk.
	assertVerificationFailure(t, "v2-only-with-ecdsa-sha256-p256-sig-does-not-verify.apk", "verification failed")
}

func TestV3SignatureDoesNotMatchSignedDataRejected(t *testing.T) {
	// APK signed with v3 scheme only, but the signature over signed-data does not verify

	// Bitflip in DSA signature. Based on v3-only-with-dsa-sha256-2048.apk.
	assertVerificationFailure(t, "v3-only-with-dsa-sha256-2048-sig-does-not-verify.apk", "failed to verify signature")

	// Bitflip in signed data. Based on v3-only-with-rsa-pkcs1-sha256-3072.apk
	assertVerificationFailure(t, "v3-only-with-rsa-pkcs1-sha256-3072-sig-does-not-verify.apk", "failed to verify signature")

	// Based on v3-only-with-ecdsa-sha512-p521 with the signature ID changed to be ECDSA with
	// SHA-256.
	assertVerificationFailure(t, "v3-only-with-ecdsa-sha512-p521-sig-does-not-verify.apk", "failed to verify signature")
}

func TestV2RsaPssSignatureDoesNotMatchSignedDataRejected(t *testing.T) {
	// APK signed with v2 scheme only, but the signature over signed-data does not verify.
	// Signature claims to be RSA PSS with SHA-256 and 32 bytes of salt, but is actually using 0
	// bytes of salt. Based on v2-only-with-rsa-pkcs1-sha256-2048.apk. Obtained by modifying APK
	// signer to use the wrong amount of salt.
	assertVerificationFailure(t, "v2-only-with-rsa-pss-sha256-2048-sig-does-not-verify.apk", "verification error")
}

func TestV2ContentDigestMismatchRejected(t *testing.T) {
	// APK signed with v2 scheme only, but the digest of contents does not match the digest
	// stored in signed-data
	// Based on v2-only-with-rsa-pkcs1-sha512-4096.apk. Obtained by modifying APK signer to
	// flip the leftmost bit in content digest before signing signed-data.
	assertVerificationFailure(t, "v2-only-with-rsa-pkcs1-sha512-4096-digest-mismatch.apk", "digest of contents did not verify")
	// Based on v2-only-with-ecdsa-sha256-p256.apk. Obtained by modifying APK signer to flip the
	// leftmost bit in content digest before signing signed-data.
	assertVerificationFailure(t, "v2-only-with-ecdsa-sha256-p256-digest-mismatch.apk", "digest of contents did not verify")
}

func TestV3ContentDigestMismatchRejected(t *testing.T) {
	// APK signed with v3 scheme only, but the digest of contents does not match the digest
	// stored in signed-data.

	// Based on v3-only-with-rsa-pkcs1-sha512-8192. Obtained by flipping a bit in the local
	// file header of the APK.
	assertVerificationFailure(t, "v3-only-with-rsa-pkcs1-sha512-8192-digest-mismatch.apk", "digest of contents did not verify")

	// Based on v3-only-with-dsa-sha256-3072.apk. Obtained by modifying APK signer to flip the
	// leftmost bit in content digest before signing signed-data.
	assertVerificationFailure(t, "v3-only-with-dsa-sha256-3072-digest-mismatch.apk", "digest of contents did not verify")
}

func TestNoApkSignatureSchemeBlockRejected(t *testing.T) {
	// APK signed with v2 scheme only, but the rules for verifying APK Signature Scheme v2
	// signatures say that this APK must not be verified using APK Signature Scheme v2.
	// Obtained from v2-only-with-rsa-pkcs1-sha512-4096.apk by flipping a bit in the magic
	// field in the footer of APK Signing Block. This makes the APK Signing Block disappear.
	assertVerificationFailure(t, "v2-only-wrong-apk-sig-block-magic.apk", "No valid MANIFEST.SF")
	// Obtained by modifying APK signer to insert "GARBAGE" between ZIP Central Directory and
	// End of Central Directory. The APK is otherwise fine and is signed with APK Signature
	// Scheme v2. Based on v2-only-with-rsa-pkcs1-sha256.apk.
	assertVerificationFailure(t, "v2-only-garbage-between-cd-and-eocd.apk", "No valid MANIFEST.SF")
	// Obtained by modifying the size in APK Signature Block header. Based on
	// v2-only-with-ecdsa-sha512-p521.apk.
	assertVerificationFailure(t, "v2-only-apk-sig-block-size-mismatch.apk", "No valid MANIFEST.SF")
	// Obtained by modifying the ID under which APK Signature Scheme v2 Block is stored in
	// APK Signing Block and by modifying the APK signer to not insert anti-stripping
	// protections into JAR Signature. The APK should appear as having no APK Signature Scheme
	// v2 Block and should thus successfully verify using JAR Signature Scheme.
	assertVerified(t, "v1-with-apk-sig-block-but-without-apk-sig-scheme-v2-block.apk")
}

func TestNoV3ApkSignatureSchemeBlockRejected(t *testing.T) {
	// Obtained from v3-only-with-ecdsa-sha512-p384.apk by flipping a bit in the magic field
	// in the footer of the APK Signing Block.
	assertVerificationFailure(t, "v3-only-with-ecdsa-sha512-p384-wrong-apk-sig-block-magic.apk", "No valid MANIFEST.SF")

	// Obtained from v3-only-with-rsa-pkcs1-sha512-4096.apk by modifying the size in the APK
	// Signature Block header and footer.
	assertVerificationFailure(t, "v3-only-with-rsa-pkcs1-sha512-4096-apk-sig-block-size-mismatch.apk", "No valid MANIFEST.SF")
}

func TestTruncatedZipCentralDirectoryRejected(t *testing.T) {
	// Obtained by modifying APK signer to truncate the ZIP Central Directory by one byte. The
	// APK is otherwise fine and is signed with APK Signature Scheme v2. Based on
	// v2-only-with-rsa-pkcs1-sha256.apk
	assertVerificationFailure(t, "v2-only-truncated-cd.apk", "No valid MANIFEST.SF")
}

func TestV2UnknownPairIgnoredInApkSigningBlock(t *testing.T) {
	// Obtained by modifying APK signer to emit an unknown ID-value pair into APK Signing Block
	// before the ID-value pair containing the APK Signature Scheme v2 Block. The unknown
	// ID-value should be ignored.
	assertVerifiedSdk(t, "v2-only-unknown-pair-in-apk-sig-block.apk", apilevel.V7_1_Nougat, apilevel.V_AnyMax)
}

func TestV3UnknownPairIgnoredInApkSigningBlock(t *testing.T) {
	// Obtained by modifying APK signer to emit an unknown ID value pair into APK Signing Block
	// before the ID value pair containing the APK Signature Scheme v3 Block. The unknown
	// ID value should be ignored.
	assertVerifiedSdk(t, "v3-only-unknown-pair-in-apk-sig-block.apk", apilevel.V9_0_Pie, apilevel.V_AnyMax)
}

func TestV2UnknownSignatureAlgorithmsIgnored(t *testing.T) {
	// APK is signed with a known signature algorithm and with a couple of unknown ones.
	// Obtained by modifying APK signer to use "unknown" signature algorithms in addition to
	// known ones.
	assertVerifiedSdk(t, "v2-only-with-ignorable-unsupported-sig-algs.apk", apilevel.V7_1_Nougat, apilevel.V_AnyMax)
}

func TestV3UnknownSignatureAlgorithmsIgnored(t *testing.T) {
	// APK is signed with a known signature algorithm and a couple of unknown ones.
	// Obtained by modifying APK signer to use "unknown" signature algorithms in addition to
	// known ones.
	assertVerifiedSdk(t, "v3-only-with-ignorable-unsupported-sig-algs.apk", apilevel.V9_0_Pie, apilevel.V_AnyMax)
}

func TestV3WithOnlyUnknownSignatureAlgorithmsRejected(t *testing.T) {
	// APK is only signed with an unknown signature algorithm. Obtained by modifying APK
	// signer's ID for a known signature algorithm.
	assertVerificationFailure(t, "v3-only-no-supported-sig-algs.apk", "no supported signatures")
}

func TestV2UnknownAdditionalAttributeIgnored(t *testing.T) {
	// APK's v2 signature contains an unknown additional attribute, but is otherwise fine.
	// Obtained by modifying APK signer to output an additional attribute with ID 0x01020304
	// and value 0x05060708.
	assertVerifiedSdk(t, "v2-only-unknown-additional-attr.apk", apilevel.V7_1_Nougat, apilevel.V_AnyMax)
}

func TestV3UnknownAdditionalAttributeIgnored(t *testing.T) {
	// APK's v3 signature contains unknown additional attributes before and after the lineage.
	// Obtained by modifying APK signer to output additional attributes with IDs 0x11223344
	// and 0x99aabbcc with values 0x55667788 and 0xddeeff00
	assertVerifiedSdk(t, "v3-only-unknown-additional-attr.apk", apilevel.V9_0_Pie, apilevel.V_AnyMax)

	// APK's v2 and v3 signatures contain unknown additional attributes before and after the
	// anti-stripping and lineage attributes.
	assertVerifiedSdk(t, "v2v3-unknown-additional-attr.apk", apilevel.V9_0_Pie, apilevel.V_AnyMax)
}

func TestV2MismatchBetweenSignaturesAndDigestsBlockRejected(t *testing.T) {
	// APK is signed with a single signature algorithm, but the digests block claims that it is
	// signed with two different signature algorithms. Obtained by modifying APK Signer to
	// emit an additional digest record with signature algorithm 0x12345678.
	assertVerificationFailure(t, "v2-only-signatures-and-digests-block-mismatch.apk", "signature algorithms don't match")
}

func TestV3MismatchBetweenSignaturesAndDigestsBlockRejected(t *testing.T) {
	// APK is signed with a single signature algorithm, but the digests block claims that it is
	// signed with two different signature algorithms. Obtained by modifying APK Signer to
	// emit an additional digest record with signature algorithm 0x11223344.
	assertVerificationFailure(t, "v3-only-signatures-and-digests-block-mismatch.apk", "signature algorithms don't match")
}

func TestV2MismatchBetweenPublicKeyAndCertificateRejected(t *testing.T) {
	// APK is signed with v2 only. The public key field does not match the public key in the
	// leaf certificate. Obtained by modifying APK signer to write out a modified leaf
	// certificate where the RSA modulus has a bitflip.
	assertVerificationFailure(t, "v2-only-cert-and-public-key-mismatch.apk", "Public key mismatch between certificate and signature")
}

func TestV3MismatchBetweenPublicKeyAndCertificateRejected(t *testing.T) {
	// APK is signed with v3 only. The public key field does not match the public key in the
	// leaf certificate. Obtained by modifying APK signer to write out a modified leaf
	// certificate where the RSA modulus has a bitflip.
	assertVerificationFailure(t, "v3-only-cert-and-public-key-mismatch.apk", "Public key mismatch")
}

func TestV2SignerBlockWithNoCertificatesRejected(t *testing.T) {
	// APK is signed with v2 only. There are no certificates listed in the signer block.
	// Obtained by modifying APK signer to output no certificates.
	assertVerificationFailure(t, "v2-only-no-certs-in-sig.apk", "No certificates listed")
}

func TestV3SignerBlockWithNoCertificatesRejected(t *testing.T) {
	// APK is signed with v3 only. There are no certificates listed in the signer block.
	// Obtained by modifying APK signer to output no certificates.
	assertVerificationFailure(t, "v3-only-no-certs-in-sig.apk", "No certificates listed")
}

func TestTwoSignersAccepted(t *testing.T) {
	// APK signed by two different signers
	assertVerified(t, "two-signers.apk")
	assertVerified(t, "v1-only-two-signers.apk")
	assertVerifiedSdk(t, "v2-only-two-signers.apk", apilevel.V7_1_Nougat, apilevel.V_AnyMax)
}

func TestV2TwoSignersRejectedWhenOneBroken(t *testing.T) {
	// Bitflip in the ECDSA signature of second signer. Based on two-signers.apk.
	// This asserts that breakage in any signer leads to rejection of the APK.
	assertVerificationFailure(t, "two-signers-second-signer-v2-broken.apk", "verification failed")
}

func TestV2TwoSignersRejectedWhenOneWithoutSignatures(t *testing.T) {
	// APK v2-signed by two different signers. However, there are no signatures for the second
	// signer.
	assertVerificationFailure(t, "v2-only-two-signers-second-signer-no-sig.apk", "no signatures found")
}

func TestV2TwoSignersRejectedWhenOneWithoutSupportedSignatures(t *testing.T) {
	// APK v2-signed by two different signers. However, there are no supported signatures for
	// the second signer.
	assertVerificationFailure(t, "v2-only-two-signers-second-signer-no-supported-sig.apk", "no supported signatures found")
}

func TestV2MaxSupportedSignersAccepted(t *testing.T) {
	assertVerifiedSdk(t, "v2-only-10-signers.apk", apilevel.V7_1_Nougat, apilevel.V_AnyMax)
}

func TestV2MoreThanMaxSupportedSignersRejected(t *testing.T) {
	assertVerificationFailureSdk(t, "v2-only-11-signers.apk", apilevel.V7_1_Nougat, apilevel.V_AnyMax, "APK Signature Scheme V2 only supports a maximum")
}

func TestCorrectCertUsedFromPkcs7SignedDataCertsSet(t *testing.T) {
	// Obtained by prepending the rsa-1024 certificate to the PKCS#7 SignedData certificates set
	// of v1-only-with-rsa-pkcs1-sha1-1.2.840.113549.1.1.1-2048.apk META-INF/CERT.RSA. The certs
	// (in the order of appearance in the file) are thus: rsa-1024, rsa-2048. The package's
	// signing cert is rsa-2048.
	res := assertVerified(t, "v1-only-pkcs7-cert-bag-first-cert-not-used.apk")

	if len(res.SignerCerts) != 1 || len(res.SignerCerts[0]) != 1 {
		t.Fatalf("Wrong cert count")
	}

	hash := sha256.Sum256(res.SignerCerts[0][0].Raw)
	if hex.EncodeToString(hash[:]) != "fb5dbd3c669af9fc236c6991e6387b7f11ff0590997f22d0f5c74ff40e04fca8" {
		t.Fatalf("Invalid cert hash")
	}
}

func TestV1SchemeSignatureCertNotReencoded(t *testing.T) {
	// Regression test for b/30148997 and b/18228011. When PackageManager does not preserve the
	// original encoded form of signing certificates, bad things happen, such as rejection of
	// completely valid updates to apps. The issue in b/30148997 and b/18228011 was that
	// PackageManager started re-encoding signing certs into DER. This normally produces exactly
	// the original form because X.509 certificates are supposed to be DER-encoded. However, a
	// small fraction of Android apps uses X.509 certificates which are not DER-encoded. For
	// such apps, re-encoding into DER changes the serialized form of the certificate, creating
	// a mismatch with the serialized form stored in the PackageManager database, leading to the
	// rejection of updates for the app.
	//
	// v1-only-with-rsa-1024-cert-not-der.apk cert's signature is not DER-encoded. It is
	// BER-encoded, with length encoded as two bytes instead of just one.
	// v1-only-with-rsa-1024-cert-not-der.apk META-INF/CERT.RSA was obtained from
	// v1-only-with-rsa-1024.apk META-INF/CERT.RSA by manually modifying the ASN.1 structure.
	res := assertVerified(t, "v1-only-with-rsa-1024-cert-not-der.apk")

	if len(res.SignerCerts) != 1 || len(res.SignerCerts[0]) != 1 {
		t.Fatalf("Wrong cert count")
	}

	// apkverifier is not expected to pass this, we are not extracting the certs, so whatever
	t.Skip("test not relevant for apkverifier")

	hash := sha256.Sum256(res.SignerCerts[0][0].Raw)
	if hex.EncodeToString(hash[:]) != "c5d4535a7e1c8111687a8374b2198da6f5ff8d811a7a25aa99ef060669342fa9" {
		t.Fatalf("Invalid cert hash")
	}
}

func TestV1SchemeSignatureCertNotReencoded2(t *testing.T) {
	// Regression test for b/30148997 and b/18228011. When PackageManager does not preserve the
	// original encoded form of signing certificates, bad things happen, such as rejection of
	// completely valid updates to apps. The issue in b/30148997 and b/18228011 was that
	// PackageManager started re-encoding signing certs into DER. This normally produces exactly
	// the original form because X.509 certificates are supposed to be DER-encoded. However, a
	// small fraction of Android apps uses X.509 certificates which are not DER-encoded. For
	// such apps, re-encoding into DER changes the serialized form of the certificate, creating
	// a mismatch with the serialized form stored in the PackageManager database, leading to the
	// rejection of updates for the app.
	//
	// v1-only-with-rsa-1024-cert-not-der2.apk cert's signature is not DER-encoded. It is
	// BER-encoded, with the BIT STRING value containing an extraneous leading 0x00 byte.
	// v1-only-with-rsa-1024-cert-not-der2.apk META-INF/CERT.RSA was obtained from
	// v1-only-with-rsa-1024.apk META-INF/CERT.RSA by manually modifying the ASN.1 structure.
	res := assertVerified(t, "v1-only-with-rsa-1024-cert-not-der2.apk")

	if len(res.SignerCerts) != 1 || len(res.SignerCerts[0]) != 1 {
		t.Fatalf("Wrong cert count")
	}

	// apkverifier is not expected to pass this, we are not extracting the certs, so whatever
	t.Skip("test not relevant for apkverifier")

	hash := sha256.Sum256(res.SignerCerts[0][0].Raw)
	if hex.EncodeToString(hash[:]) != "da3da398de674541313deed77218ce94798531ea5131bb9b1bb4063ba4548cfb" {
		t.Fatalf("Invalid cert hash")
	}
}

func TestMaxSizedZipEocdCommentAccepted(t *testing.T) {
	// Obtained by modifying apksigner to produce a max-sized (0xffff bytes long) ZIP End of
	// Central Directory comment, and signing the original.apk using the modified apksigner.
	assertVerified(t, "v1-only-max-sized-eocd-comment.apk")
	assertVerifiedSdk(t, "v2-only-max-sized-eocd-comment.apk", apilevel.V7_1_Nougat, apilevel.V_AnyMax)
}

func TestEmptyApk(t *testing.T) {
	// Unsigned empty ZIP archive
	assertVerificationFailureSdk(t, "empty-unsigned.apk", apilevel.V1_5_Cupcake, apilevel.V_AnyMax, "No valid MANIFEST.SF")
	// JAR-signed empty ZIP archive
	assertVerificationFailureSdk(t, "v1-only-empty.apk", apilevel.V4_3_JellyBean, apilevel.V_AnyMax, "No manifest entry")
	// APK Signature Scheme v2 signed empty ZIP archive
	assertVerificationFailureSdk(t, "v2-only-empty.apk", apilevel.V7_1_Nougat, apilevel.V_AnyMax, "No valid MANIFEST.SF")
	// APK Signature Scheme v3 signed empty ZIP archive
	assertVerificationFailureSdk(t, "v3-only-empty.apk", apilevel.V9_0_Pie, apilevel.V_AnyMax, "No valid MANIFEST.SF")
}

func TestTargetSandboxVersion2AndHigher(t *testing.T) {
	// This APK (and its variants below) use minSdkVersion 18, meaning it needs to be signed
	// with v1 and v2 schemes
	// This APK is signed with v1 and v2 schemes and thus should verify
	assertVerified(t, "targetSandboxVersion-2.apk")
	// v1 signature is needed only if minSdkVersion is lower than 24
	assertVerificationFailure(t, "v2-only-targetSandboxVersion-2.apk", "No valid MANIFEST.SF")
	assertVerifiedSdk(t, "v2-only-targetSandboxVersion-2.apk", apilevel.V7_0_Nougat, apilevel.V_AnyMax)
	// v2 signature is required
	assertVerificationFailure(t, "v1-only-targetSandboxVersion-2.apk", "no valid signature for sandbox version")
	assertVerificationFailure(t, "unsigned-targetSandboxVersion-2.apk", "no valid signature for sandbox version")
	// minSdkVersion 28, meaning v1 signature not needed
	assertVerified(t, "v2-only-targetSandboxVersion-3.apk")
}

func TestTargetSdkMinSchemeVersionNotMet(t *testing.T) {
	assertVerificationFailure(t, "v1-ec-p256-targetSdk-30.apk", "target SDK version 30 requires a minimum of signature scheme v2")
}

func TestTargetSdkMinSchemeVersionMet(t *testing.T) {
	assertVerified(t, "v2-ec-p256-targetSdk-30.apk")
	assertVerified(t, "v3-ec-p256-targetSdk-30.apk")
}

func TestTargetSdkMinSchemeVersionNotMetMaxLessThanTarget(t *testing.T) {
	assertVerifiedSdk(t, "v1-ec-p256-targetSdk-30.apk", apilevel.V_AnyMin, apilevel.V10_0_Ten)
}

func TestTargetSdkNoUsesSdkElement(t *testing.T) {
	assertVerified(t, "v1-only-no-uses-sdk.apk")
}

func TestV1MultipleDigestAlgsInManifestAndSignatureFile(t *testing.T) {
	// MANIFEST.MF contains SHA-1 and SHA-256 digests for each entry, .SF contains only SHA-1
	// digests. This file was obtained by:
	//   jarsigner -sigalg SHA256withRSA -digestalg SHA-256 ... <file> ...
	//   jarsigner -sigalg SHA1withRSA -digestalg SHA1 ... <same file> ...
	assertVerified(t, "v1-sha1-sha256-manifest-and-sha1-sf.apk")
	// MANIFEST.MF and .SF contain SHA-1 and SHA-256 digests for each entry. This file was
	// obtained by modifying apksigner to output multiple digests.
	assertVerified(t, "v1-sha1-sha256-manifest-and-sf.apk")
	// One of the digests is wrong in either MANIFEST.MF or .SF. These files were obtained by
	// modifying apksigner to output multiple digests and to flip a bit to create a wrong
	// digest.
	// SHA-1 digests in MANIFEST.MF are wrong, but SHA-256 digests are OK.
	// The APK will fail to verify on API Level 17 and lower, but will verify on API Level 18
	// and higher.
	assertVerificationFailure(t, "v1-sha1-sha256-manifest-and-sf-with-sha1-wrong-in-manifest.apk", "No matching hash for")
	assertVerificationFailureSdk(t, "v1-sha1-sha256-manifest-and-sf-with-sha1-wrong-in-manifest.apk", apilevel.V_AnyMin, apilevel.V4_2_JellyBean, "No matching hash for")
	assertVerifiedSdk(t, "v1-sha1-sha256-manifest-and-sf-with-sha1-wrong-in-manifest.apk", apilevel.V4_3_JellyBean, apilevel.V_AnyMax)
	// SHA-1 digests in .SF are wrong, but SHA-256 digests are OK.
	// The APK will fail to verify on API Level 17 and lower, but will verify on API Level 18
	// and higher.
	assertVerificationFailure(t, "v1-sha1-sha256-manifest-and-sf-with-sha1-wrong-in-sf.apk", "Invalid hash of manifest entry")
	assertVerificationFailureSdk(t, "v1-sha1-sha256-manifest-and-sf-with-sha1-wrong-in-sf.apk", apilevel.V_AnyMin, apilevel.V4_2_JellyBean, "Invalid hash of manifest entry")
	assertVerifiedSdk(t, "v1-sha1-sha256-manifest-and-sf-with-sha1-wrong-in-sf.apk", apilevel.V4_3_JellyBean, apilevel.V_AnyMax)
	// SHA-256 digests in MANIFEST.MF are wrong, but SHA-1 digests are OK.
	// The APK will fail to verify on API Level 18 and higher, but will verify on API Level 17
	// and lower.
	assertVerificationFailure(t, "v1-sha1-sha256-manifest-and-sf-with-sha256-wrong-in-manifest.apk", "No matching hash for")
	assertVerificationFailureSdk(t, "v1-sha1-sha256-manifest-and-sf-with-sha256-wrong-in-manifest.apk", apilevel.V4_3_JellyBean, apilevel.V_AnyMax, "No matching hash for")
	assertVerifiedSdk(t, "v1-sha1-sha256-manifest-and-sf-with-sha256-wrong-in-manifest.apk", apilevel.V_AnyMin, apilevel.V4_2_JellyBean)
	// SHA-256 digests in .SF are wrong, but SHA-1 digests are OK.
	// The APK will fail to verify on API Level 18 and higher, but will verify on API Level 17
	// and lower.
	assertVerificationFailure(t, "v1-sha1-sha256-manifest-and-sf-with-sha256-wrong-in-sf.apk", "Invalid hash of manifest entry")
	assertVerificationFailureSdk(t, "v1-sha1-sha256-manifest-and-sf-with-sha256-wrong-in-sf.apk", apilevel.V4_3_JellyBean, apilevel.V_AnyMax, "Invalid hash of manifest entry")
	assertVerifiedSdk(t, "v1-sha1-sha256-manifest-and-sf-with-sha256-wrong-in-sf.apk", apilevel.V_AnyMin, apilevel.V4_2_JellyBean)
}

func TestV1WithUnsupportedCharacterInZipEntryName(t *testing.T) {
	// Android Package Manager does not support ZIP entry names containing CR or LF
	assertVerificationFailure(t, "v1-only-with-cr-in-entry-name.apk", anyErrorString)
	assertVerificationFailure(t, "v1-only-with-lf-in-entry-name.apk", anyErrorString)
}

func TestWeirdZipCompressionMethod(t *testing.T) {
	// Any ZIP compression method other than STORED is treated as DEFLATED by Android.
	// This APK declares compression method 21 (neither STORED nor DEFLATED) for CERT.RSA entry,
	// but the entry is actually Deflate-compressed.
	assertVerified(t, "weird-compression-method.apk")
}

func TestZipCompressionMethodMismatchBetweenLfhAndCd(t *testing.T) {
	// Android Package Manager ignores compressionMethod field in Local File Header and always
	// uses the compressionMethod from Central Directory instead.
	// In this APK, compression method of CERT.RSA is declared as STORED in Local File Header
	// and as DEFLATED in Central Directory. The entry is actually Deflate-compressed.
	assertVerified(t, "mismatched-compression-method.apk")
}

func TestV1SignedAttrs(t *testing.T) {
	// We do not care, it installs on real devices
	// 0f2b96555e09ef5dd0e18c360c0b1b35666f68d0ed312586a259a3d1ee39b68a

	apk := "v1-only-with-signed-attrs.apk"
	//assertVerificationFailureSdk(t, apk, apilevel.V4_3_JellyBean, apilevel.V_AnyMax, "APKs with Signed Attributes broken on platforms")
	assertVerifiedSdk(t, apk, apilevel.V4_3_JellyBean, apilevel.V_AnyMax)
	assertVerifiedSdk(t, apk, apilevel.V4_4_KitKat, apilevel.V_AnyMax)
	apk = "v1-only-with-signed-attrs-signerInfo1-good-signerInfo2-good.apk"
	//assertVerificationFailureSdk(t, apk, apilevel.V4_3_JellyBean, apilevel.V_AnyMax, "APKs with Signed Attributes broken on platforms")
	assertVerifiedSdk(t, apk, apilevel.V4_3_JellyBean, apilevel.V_AnyMax)
	assertVerifiedSdk(t, apk, apilevel.V4_4_KitKat, apilevel.V_AnyMax)
}

func TestV1SignedAttrsNotInDerOrder(t *testing.T) {
	// Android does not re-order SignedAttributes despite it being a SET OF. Pre-N, Android
	// treated them as SEQUENCE OF, meaning no re-ordering is necessary. From N onwards, it
	// treats them as SET OF, but does not re-encode into SET OF during verification if all
	// attributes parsed fine.
	assertVerified(t, "v1-only-with-signed-attrs-wrong-order.apk")
	assertVerified(t, "v1-only-with-signed-attrs-signerInfo1-wrong-order-signerInfo2-good.apk")
}

func TestV1SignedAttrsMissingContentType(t *testing.T) {
	// SignedAttributes must contain ContentType. Pre-N, Android ignores this requirement.
	// Android N onwards rejects such APKs.
	apk := "v1-only-with-signed-attrs-missing-content-type.apk"
	assertVerifiedSdk(t, apk, apilevel.V_AnyMin, apilevel.V6_0_Marshmallow)
	assertVerificationFailure(t, apk, "failed to parse signed content type")
	// Assert that this issue fails verification of the entire signature block, rather than
	// skipping the broken SignerInfo. The second signer info SignerInfo verifies fine, but
	// verification does not get there.
	apk = "v1-only-with-signed-attrs-signerInfo1-missing-content-type-signerInfo2-good.apk"
	assertVerifiedSdk(t, apk, apilevel.V_AnyMin, apilevel.V6_0_Marshmallow)
	assertVerificationFailure(t, apk, "failed to parse signed content type")
}

func TestV1SignedAttrsWrongContentType(t *testing.T) {
	// ContentType of SignedAttributes must equal SignedData.encapContentInfo.eContentType.
	// Pre-N, Android ignores this requirement.
	// From N onwards, Android rejects such SignerInfos.
	apk := "v1-only-with-signed-attrs-wrong-content-type.apk"
	assertVerifiedSdk(t, apk, apilevel.V_AnyMin, apilevel.V6_0_Marshmallow)
	assertVerificationFailure(t, apk, "PKCS7 content type does not match")
	// First SignerInfo does not verify on Android N and newer, but verification moves on to the
	// second SignerInfo, which verifies.
	apk = "v1-only-with-signed-attrs-signerInfo1-wrong-content-type-signerInfo2-good.apk"
	assertVerifiedSdk(t, apk, apilevel.V_AnyMin, apilevel.V6_0_Marshmallow)
	assertVerifiedSdk(t, apk, apilevel.V7_0_Nougat, apilevel.V_AnyMax)
	// Although the APK's signature verifies on pre-N and N+, we reject such APKs because the
	// APK's verification results in different verified SignerInfos (and thus potentially
	// different signing certs) between pre-N and N+.
	assertVerificationFailure(t, apk, "PKCS7 content type does not match")
}

func TestV1SignedAttrsMissingDigest(t *testing.T) {
	// Content digest must be present in SignedAttributes
	apk := "v1-only-with-signed-attrs-missing-digest.apk"
	assertVerificationFailureSdk(t, apk, apilevel.V_AnyMin, apilevel.V6_0_Marshmallow, "failed to parse signed message digest")
	assertVerificationFailureSdk(t, apk, apilevel.V7_0_Nougat, apilevel.V_AnyMax, "failed to parse signed message digest")
	// Assert that this issue fails verification of the entire signature block, rather than
	// skipping the broken SignerInfo. The second signer info SignerInfo verifies fine, but
	// verification does not get there.
	apk = "v1-only-with-signed-attrs-signerInfo1-missing-digest-signerInfo2-good.apk"
	assertVerificationFailureSdk(t, apk, apilevel.V_AnyMin, apilevel.V6_0_Marshmallow, "failed to parse signed message digest")
	assertVerificationFailureSdk(t, apk, apilevel.V7_0_Nougat, apilevel.V_AnyMax, "failed to parse signed message digest")
}

func TestV1SignedAttrsMultipleGoodDigests(t *testing.T) {
	// Only one content digest must be present in SignedAttributes
	apk := "v1-only-with-signed-attrs-multiple-good-digests.apk"
	assertVerificationFailureSdk(t, apk, apilevel.V_AnyMin, apilevel.V6_0_Marshmallow, "failed to parse signed message digest")
	assertVerificationFailureSdk(t, apk, apilevel.V7_0_Nougat, apilevel.V_AnyMax, "failed to parse signed message digest")
	// Assert that this issue fails verification of the entire signature block, rather than
	// skipping the broken SignerInfo. The second signer info SignerInfo verifies fine, but
	// verification does not get there.
	apk = "v1-only-with-signed-attrs-signerInfo1-multiple-good-digests-signerInfo2-good.apk"
	assertVerificationFailureSdk(t, apk, apilevel.V_AnyMin, apilevel.V6_0_Marshmallow, "failed to parse signed message digest")
	assertVerificationFailureSdk(t, apk, apilevel.V7_0_Nougat, apilevel.V_AnyMax, "failed to parse signed message digest")
}

func TestV1SignedAttrsWrongDigest(t *testing.T) {
	// Content digest in SignedAttributes does not match the contents
	apk := "v1-only-with-signed-attrs-wrong-digest.apk"
	assertVerificationFailureSdk(t, apk, apilevel.V_AnyMin, apilevel.V6_0_Marshmallow, "signedAttributes hash mismatch")
	assertVerificationFailureSdk(t, apk, apilevel.V7_0_Nougat, apilevel.V_AnyMax, "signedAttributes hash mismatch")
	// First SignerInfo does not verify, but Android N and newer moves on to the second
	// SignerInfo, which verifies.
	apk = "v1-only-with-signed-attrs-signerInfo1-wrong-digest-signerInfo2-good.apk"
	assertVerificationFailureSdk(t, apk, apilevel.V_AnyMin, apilevel.V6_0_Marshmallow, "signedAttributes hash mismatch")
	assertVerifiedSdk(t, apk, apilevel.V7_0_Nougat, apilevel.V_AnyMax)
}

func TestV1SignedAttrsWrongSignature(t *testing.T) {
	// Signature over SignedAttributes does not verify
	apk := "v1-only-with-signed-attrs-wrong-signature.apk"
	assertVerificationFailureSdk(t, apk, apilevel.V_AnyMin, apilevel.V6_0_Marshmallow, "verification error")
	assertVerificationFailureSdk(t, apk, apilevel.V7_0_Nougat, apilevel.V_AnyMax, "verification error")
	// First SignerInfo does not verify, but Android N and newer moves on to the second
	// SignerInfo, which verifies.
	apk = "v1-only-with-signed-attrs-signerInfo1-wrong-signature-signerInfo2-good.apk"
	assertVerificationFailureSdk(t, apk, apilevel.V_AnyMin, apilevel.V6_0_Marshmallow, "verification error")
	assertVerifiedSdk(t, apk, apilevel.V7_0_Nougat, apilevel.V_AnyMax)
}

// Lineage tests
func TestLineageFromAPKContainsExpectedSigners(t *testing.T) {
	assertLineageHasCerts(t, "v1v2v3-with-rsa-2048-lineage-3-signers.apk", apilevel.V7_0_Nougat, []string{
		FIRST_RSA_2048_SIGNER_RESOURCE_NAME, SECOND_RSA_2048_SIGNER_RESOURCE_NAME, THIRD_RSA_2048_SIGNER_RESOURCE_NAME,
	})
}

func TestGetResultLineage(t *testing.T) {
	assertLineageHasCerts(t, "v31-tgt-33-no-v3-attr.apk", apilevel.V8_0_Oreo, []string{
		FIRST_RSA_2048_SIGNER_RESOURCE_NAME, SECOND_RSA_2048_SIGNER_RESOURCE_NAME,
	})
}

func TestGetResultV3Lineage(t *testing.T) {
	assertLineageHasCerts(t, "v3-rsa-2048_2-tgt-dev-release.apk", apilevel.V7_0_Nougat, []string{
		FIRST_RSA_2048_SIGNER_RESOURCE_NAME, SECOND_RSA_2048_SIGNER_RESOURCE_NAME,
	})
}

func TestGetResultNoLineage(t *testing.T) {
	res := assertVerificationFailureSdk(t, "v31-empty-lineage-no-v3.apk", apilevel.V7_0_Nougat, apilevel.V_AnyMax,
		"The APK contains a v3.1 signing block without a v3.0 base block")
	if res.SigningBlockResult == nil {
		t.Fatalf("no signing block found")
	} else if res.SigningBlockResult.SigningLineage != nil {
		t.Fatalf("signing lineage found")
	}
}

func TestGetResultNoV31Apk(t *testing.T) {
	res := assertVerifiedSdk(t, "v3-rsa-2048_2-tgt-dev-release.apk", apilevel.V7_0_Nougat, apilevel.V_AnyMax)
	if res.SigningBlockResult == nil {
		t.Fatalf("no signing block found")
	}

	if res.SigningSchemeId != 3 {
		t.Fatalf("Invalid scheme id, got %d and expected 3", res.SigningSchemeId)
	}
}

func TestGetResultFromV3BlockFromV31SignedApk(t *testing.T) {
	res := assertVerifiedSdk(t, "v31-rsa-2048_2-tgt-33-1-tgt-28.apk", apilevel.V7_0_Nougat, apilevel.V_AnyMax)
	if res.SigningBlockResult == nil {
		t.Fatalf("no signing block found")
	}

	if res.SigningSchemeId != 31 {
		t.Fatalf("Invalid scheme id, got %d and expected 31", res.SigningSchemeId)
	}

	v3result := res.SigningBlockResult.ExtraResults[3]
	if v3result == nil {
		t.Fatalf("Extra V3 result not found")
	}

	if v3result.SigningLineage != nil {
		t.Fatalf("signing lineage found")
	}
}

func TestGetResultContainsLineageErrors(t *testing.T) {
	res := assertVerificationFailureSdk(t, "v31-2elem-incorrect-lineage.apk", apilevel.V9_0_Pie, apilevel.V_AnyMax,
		"failed to read signing certificate lineage attribute: failed to parse cert in node")
	if res.SigningBlockResult == nil {
		t.Fatalf("no signing block found")
	} else if res.SigningBlockResult.SigningLineage != nil {
		t.Fatalf("signing lineage found")
	}
}

func TestLineageFromAPKWithInvalidZipCDSizeFails(t *testing.T) {
	// This test verifies that attempting to read the lineage from an APK where the zip
	// sections cannot be parsed fails. This APK is based off the
	// v1v2v3-with-rsa-2048-lineage-3-signers.apk with a modified CD size in the EoCD.
	assertVerificationFailureSdk(t, "v1v2v3-with-rsa-2048-lineage-3-signers-invalid-zip.apk",
		24, apilevel.V_AnyMax, anyErrorString)
}

func TestLineageFromAPKWithNoLineageFails(t *testing.T) {
	// This is a valid APK that has only been signed with the V1 and V2 signature schemes;
	// since the lineage is an attribute in the V3 signature block this test should fail.
	assertNoLineage(t, "golden-aligned-v1v2-out.apk", true, apilevel.V_AnyMin)

	// This is a valid APK signed with the V1, V2, and V3 signature schemes, but there is no
	// lineage in the V3 signature block.
	assertNoLineage(t, "golden-aligned-v1v2v3-out.apk", true, apilevel.V_AnyMin)

	// This APK is based off the v1v2v3-with-rsa-2048-lineage-3-signers.apk with a bit flip
	// in the lineage attribute ID in the V3 signature block.
	assertNoLineage(t, "v1v2v3-with-rsa-2048-lineage-3-signers-invalid-lineage-attr.apk", false, apilevel.V9_0_Pie)
}

func TestAsn1UnprintableSchemeV1(t *testing.T) {
	_, err := apkverifier.VerifyWithSdkVersion("testdata/asn1_unprintable.apk", nil, apilevel.V_AnyMin, apilevel.V_AnyMax)
	if err == nil || !strings.Contains(err.Error(), "cannot be verified using v1 scheme, downgrade attack?") {
		t.Fatalf("Invalid result for asn1_unprintable.apk, expected 'downgrade attack' error, got %v", err)
	}
}

func TestAsn1SuperfluousLeadingZeros(t *testing.T) {
	const certBase64 = `MIICFzCCAX+gAwIBAgIaNDc4MjQzM2U6MTJmMDE4M2FjZGI6LTgwMDAwDQYJKoZIhvcNAQEFBQAwODELMAkGA1UEBhMCVVMxCTAHBgNVBAoTADEJMAcGA1UECxMAMRMwEQYDVQQDEwpteUhlcml0YWdlMB4XDTExMDMyODEyMDgxN1oXDTM2MDMyOTExMDgxN1owODELMAkGA1UEBhMCVVMxCTAHBgNVBAoTADEJMAcGA1UECxMAMRMwEQYDVQQDEwpteUhlcml0YWdlMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCbJEkZRVOOTL9v8PUV76U9Etf5OJlOZU2laM5vyMK29QrlFZ9t7Xs06ozCd/2sVkap71NM3qDXVcQ8250a2/wU6YHJYf4D6v3f+/M507FRVynYpkegwYsUddmOcJaBlqU1V7DVZD2Qi+AMF/SE6dnP6pEJCh7w1mFyMMMTCvXqGQIDAQABoxcwFTATBgNVHSUEDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQUFAAOCAIEAjY2I0M2x7QMFTTooad+fd6j43gMAzaVVGEXOLtNzAOQye1f+o/LmCB44BH0GPVUWN518e28NExY7EhfKNuhivT7R1Ht5xYMLoMCxIIsea+FCGRrzKLxJ+ncXP1KhHz/DHCB+e0TqniN1RsoXvnMEp1VxApzDQw7X78DFMiPrFPc=`
	encodedCert, _ := base64.StdEncoding.DecodeString(certBase64)
	_, err := x509andr.ParseCertificateForGo(encodedCert)
	if err != nil {
		t.Fatal("failed to parse cert", err)
	}
}

func TestVerifySignatureNegativeModulusConscryptProvider(t *testing.T) {
	assertVerified(t, "v1v2v3-rsa-2048-negmod-in-cert.apk")
	assertVerifiedSdk(t, "v1v2v3-rsa-2048-negmod-in-cert.apk", apilevel.V_AnyMin, apilevel.V6_0_Marshmallow)
}

func TestVerifyV31RotationTarget34(t *testing.T) {
	assertVerifiedWithSigners(t, "v31-rsa-2048_2-tgt-10000-1-tgt-28.apk", true,
		[]string{FIRST_RSA_2048_SIGNER_RESOURCE_NAME, SECOND_RSA_2048_SIGNER_RESOURCE_NAME})
	// assertV31SignerTargetsMinApiLevel(result, SECOND_RSA_2048_SIGNER_RESOURCE_NAME, 10000);
}

func TestVerifyV31MissingStrippingAttr(t *testing.T) {
	res := assertVerified(t, "v31-tgt-33-no-v3-attr.apk")
	assertWarning(t, res, "does not contain the attribute to detect if this signature is stripped")
}

func TestVerifyV31MissingV31Block(t *testing.T) {
	assertVerificationFailureSdk(t, "v31-block-stripped-v3-attr-value-33.apk", apilevel.V10_0_Ten, apilevel.V_AnyMax,
		"The v3 signer indicates key rotation should be supported starting from SDK version 33, but a v3.1 block")
	assertVerifiedSdk(t, "v31-block-stripped-v3-attr-value-33.apk", apilevel.V_AnyMin, apilevel.V13_0_TIRAMISU-1)
}

func TestVerifyV31BlockWithoutV3Block(t *testing.T) {
	assertVerificationFailure(t, "v31-tgt-33-no-v3-block.apk", "The APK contains a v3.1 signing block without a v3.0 base block")
}

func TestVerifyV31RotationTargetsDevRelease(t *testing.T) {
	assertVerifiedWithSigners(t, "v31-rsa-2048_2-tgt-10000-dev-release.apk", true,
		[]string{FIRST_RSA_2048_SIGNER_RESOURCE_NAME, SECOND_RSA_2048_SIGNER_RESOURCE_NAME})
}

func TestVerifyV3RotatedSignedTargetsDevRelease(t *testing.T) {
	res := assertVerified(t, "v3-rsa-2048_2-tgt-dev-release.apk")
	assertWarning(t, res, "The rotation-targets-dev-release attribute is only supported on v3.1 signers")
}

func TestVerifyV31RotationTargets34(t *testing.T) {
	assertLineageHasCerts(t, "v31-rsa-2048_2-tgt-34-1-tgt-28.apk", apilevel.V_AnyMin,
		[]string{FIRST_RSA_2048_SIGNER_RESOURCE_NAME, SECOND_RSA_2048_SIGNER_RESOURCE_NAME})
}

func TestVerifyV31MinSdkVersionT(t *testing.T) {
	res := assertVerifiedSdk(t, "v31-rsa-2048_2-tgt-33-1-tgt-28.apk", apilevel.V13_0_TIRAMISU, apilevel.V_AnyMax)
	if res.SigningSchemeId != 31 {
		t.Fatalf("Not using scheme 31, %d", res.SigningSchemeId)
	}
}

func TestVerifyV31MinSdkVersionTTargetSdk30(t *testing.T) {
	res := assertVerifiedSdk(t, "v31-ec-p256-2-tgt-33-1-tgt-28-targetSdk-30.apk", apilevel.V13_0_TIRAMISU, apilevel.V_AnyMax)
	if res.SigningSchemeId != 31 {
		t.Fatalf("Not using scheme 31, %d", res.SigningSchemeId)
	}
}

func assertVerifiedForEach(t *testing.T, format string, names []string) {
	assertVerifiedForEachSdk(t, format, names, apilevel.V_AnyMin, apilevel.V_AnyMax)
}

func assertVerifiedForEachSdk(t *testing.T, format string, names []string, minSdkVersion, maxSdkVersion int32) {
	for _, n := range names {
		assertVerifiedSdk(t, fmt.Sprintf(format, n), minSdkVersion, maxSdkVersion)
	}
}

func assertVerified(t *testing.T, name string) apkverifier.Result {
	return assertVerifiedSdk(t, name, apilevel.V_AnyMin, apilevel.V_AnyMax)
}

func assertVerifiedSdk(t *testing.T, name string, minSdkVersion, maxSdkVersion int32) apkverifier.Result {
	res, err := verify(t, name, minSdkVersion, maxSdkVersion)
	if err == nil {
		return res
	}

	t.Fatalf("%s did not verify: %s\n%s", name, err.Error(), formatResult(t, res))
	return apkverifier.Result{}
}

func assertVerificationFailure(t *testing.T, name string, expectedError string) {
	assertVerificationFailureSdk(t, name, apilevel.V_AnyMin, apilevel.V_AnyMax, expectedError)
}

func assertVerificationFailureSdk(t *testing.T, name string, minSdkVersion, maxSdkVersion int32, expectedError string) apkverifier.Result {
	res, err := verify(t, name, minSdkVersion, maxSdkVersion)
	if err == nil || expectedError == "" {
		goto fail
	}

	if expectedError == anyErrorString {
		return res
	}

	if strings.Contains(err.Error(), expectedError) {
		return res
	}

	if res.SigningBlockResult != nil {
		for _, err := range res.SigningBlockResult.Errors {
			if strings.Contains(err.Error(), expectedError) {
				return res
			}
		}
	}

fail:
	t.Fatalf("%s was supposed to fail verification with '%s', but returned error %v instead\n%s",
		name, expectedError, err, formatResult(t, res))
	return res
}

func assertNoLineage(t *testing.T, name string, mustVerify bool, minlevel int32) {
	res, err := verify(t, name, minlevel, apilevel.V_AnyMax)
	if mustVerify != (err == nil) {
		t.Fatalf("%s has wrong verification result %v, expected %v", name, err, mustVerify)
	} else if res.SigningBlockResult == nil {
		t.Fatalf("missing signing block in %s", name)
	} else if res.SigningBlockResult.SigningLineage != nil {
		t.Fatalf("extra signing lineage in %s", name)
	}
}

func assertLineageHasCerts(t *testing.T, name string, minlevel int32, certNames []string) {
	res := assertVerifiedSdk(t, name, minlevel, apilevel.V_AnyMax)
	if res.SigningBlockResult == nil {
		t.Fatalf("no signing block found")
	} else if res.SigningBlockResult.SigningLineage == nil {
		t.Fatalf("no signing lineage found")
	}

	lin := res.SigningBlockResult.SigningLineage

	if len(certNames) != len(lin.Nodes) {
		t.Fatalf("invalid number of certs in lineage, expected %d got %d", len(certNames), len(lin.Nodes))
	}

	rsc := filepath.Join(os.Getenv("APKSIG_PATH"), "src/test/resources/com/android/apksig")
	for _, cn := range certNames {
		data, err := ioutil.ReadFile(filepath.Join(rsc, cn+".x509.pem"))
		if err != nil {
			t.Fatalf("failed to read cert file %s: %s", cn, err.Error())
		}

		block, _ := pem.Decode(data)

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("failed to parse cert %s: %s", cn, err.Error())
		}

		found := false
		for _, n := range lin.Nodes {
			if n.SigningCert.Equal(cert) {
				found = true
				break
			}
		}

		if !found {
			ci := apkverifier.NewCertInfo(cert)
			t.Fatalf("certificate %s was not found in lineage", ci.String())
		}
	}
}

func assertVerifiedWithSigners(t *testing.T, name string, rotationExpected bool, certNames []string) apkverifier.Result {
	res := assertVerified(t, name)

	var v3CertNames []string
	if res.SigningSchemeId >= 3 {
		if !rotationExpected || res.SigningSchemeId == 31 {
			v3CertNames = certNames[0:1]
		} else {
			v3CertNames = certNames[len(certNames)-1:]
		}
	}

	if res.SigningSchemeId == 31 {
		assertSigners(t, res.SigningBlockResult.ExtraResults[3].Certs, v3CertNames)
		assertSigners(t, res.SignerCerts, certNames[len(certNames)-1:])
	} else if res.SigningSchemeId == 3 {
		assertSigners(t, res.SignerCerts, v3CertNames)
	} else {
		if rotationExpected {
			certNames = certNames[0:1]
		}
		assertSigners(t, res.SignerCerts, certNames)
	}
	return res
}

func assertSigners(t *testing.T, signerCerts [][]*x509.Certificate, certNames []string) {
	expectedSigners := make(map[[32]byte]*x509.Certificate)
	signersNotFound := make(map[[32]byte]string)
	rsc := filepath.Join(os.Getenv("APKSIG_PATH"), "src/test/resources/com/android/apksig")
	for _, cn := range certNames {
		data, err := ioutil.ReadFile(filepath.Join(rsc, cn+".x509.pem"))
		if err != nil {
			t.Fatalf("failed to read cert file %s: %s", cn, err.Error())
		}

		block, _ := pem.Decode(data)

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("failed to parse cert %s: %s", cn, err.Error())
		}
		certHash := sha256.Sum256(cert.Raw)
		expectedSigners[certHash] = cert
		signersNotFound[certHash] = cn
	}

	for _, certs := range signerCerts {
		for certHash, expectedCert := range expectedSigners {
			if certs[0].Equal(expectedCert) {
				delete(signersNotFound, certHash)
			}
		}
	}

	if len(signersNotFound) != 0 {
		msg := "Failed to find signers: "
		for _, name := range signersNotFound {
			msg += name + " "
		}
		t.Fatal(msg)
	}
}

func assertWarning(t *testing.T, res apkverifier.Result, text string) {
	if res.SigningBlockResult == nil {
		t.Fatalf("no signing block found")
	}

	for _, w := range res.SigningBlockResult.Warnings {
		if strings.Contains(w, text) {
			return
		}
	}

	t.Fatalf("was supposed have warning '%s' but not found\n%s", text, formatResult(t, res))
}

func verify(t *testing.T, name string, minSdkVersion, maxSdkVersion int32) (apkverifier.Result, error) {
	apksigPath, prs := os.LookupEnv("APKSIG_PATH")
	if !prs || apksigPath == "" {
		t.Skip("This test requires APKSIG_PATH set.")
	}

	path := filepath.Join(apksigPath, "src/test/resources/com/android/apksig", name)
	return apkverifier.VerifyWithSdkVersion(path, nil, minSdkVersion, maxSdkVersion)
}

func formatResult(t *testing.T, res apkverifier.Result) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "Detected scheme: v%d\n\n", res.SigningSchemeId)
	if blk := res.SigningBlockResult; blk != nil {
		if len(blk.Errors) > 1 {
			fmt.Fprintln(&buf, "Additional errors:")
			for i := 0; i < len(blk.Errors)-1; i++ {
				fmt.Fprintf(&buf, "%s\n", blk.Errors[i].Error())
			}
			fmt.Fprintln(&buf)
		}

		if len(blk.Warnings) != 0 {
			fmt.Fprintln(&buf, "Warnings:")
			for _, w := range blk.Warnings {
				fmt.Fprintf(&buf, "%s\n", w)
			}
			fmt.Fprintln(&buf)
		}
	}

	_, picked := apkverifier.PickBestApkCert(res.SignerCerts)
	var cinfo apkverifier.CertInfo
	for i, ca := range res.SignerCerts {
		for x, cert := range ca {
			cinfo.Fill(cert)
			if picked == cert {
				fmt.Fprintf(&buf, "Chain %d, cert %d [PICKED AS BEST]:\n", i, x)
			} else {
				fmt.Fprintf(&buf, "Chain %d, cert %d:\n", i, x)
			}
			fmt.Fprintln(&buf, "algo:", cert.SignatureAlgorithm)
			fmt.Fprintln(&buf, "validfrom:", cinfo.ValidFrom)
			fmt.Fprintln(&buf, "validto:", cinfo.ValidTo)
			fmt.Fprintln(&buf, "serialnumber:", cert.SerialNumber.Text(16))
			fmt.Fprintln(&buf, "thumbprint-md5:", cinfo.Md5)
			fmt.Fprintln(&buf, "thumbprint-sha1:", cinfo.Sha1)
			fmt.Fprintln(&buf, "thumbprint-sha256:", cinfo.Sha256)
			fmt.Fprintf(&buf, "Subject:\n  %s\n", cinfo.Subject)
			fmt.Fprintf(&buf, "Issuer:\n  %s\n", cinfo.Issuer)
			fmt.Fprintln(&buf)
		}
	}

	return buf.String()
}
