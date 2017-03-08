package apkverifier

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"cutils"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"math/big"
	"os"
)

// https://source.android.com/security/apksigning/v2.html
// frameworks/base/core/java/android/util/apk/ApkSignatureSchemeV2Verifier.java

const (
	eocdRecMinSize             = 22
	eocdRecMagic               = 0x06054b50
	eocdCommentSizeOffset      = 20
	eocdCentralDirSizeOffset   = 12
	eocdCentralDirOffsetOffset = 16

	zip64LocatorSize  = 20
	zip64LocatorMagic = 0x07064b50

	apkSigBlockMinSize          = 32
	apkSigBlockMagicHi          = 0x3234206b636f6c42
	apkSigBlockMagicLo          = 0x20676953204b5041
	apkSignatureSchemeV2BlockId = 0x7109871a
)

const (
	chunkSize = 1024 * 1024

	sigRsaPssWithSha256      = 0x0101
	sigRsaPssWithSha512      = 0x0102
	sigRsaPkcs1V15WithSha256 = 0x0103
	sigRsaPkcs1V15WithSha512 = 0x0104
	sigEcdsaWithSha256       = 0x201
	sigEcdsaWithSha512       = 0x202
	sigDsaWithSha256         = 0x0301

	contentDigestChunkedSha256 = 1 // unused, crypto.SHA256 instead
	contentDigestChunkedSha512 = 2 // unused, crypto.SHA512 instead
)

var (
	errNoV2Signature = errors.New("This apk does not have V2 signature.")
	errEocdNotFound  = errors.New("EOCD record not found.")
)

type SchemeV2Result struct {
	Cert *x509.Certificate
}

type schemeV2 struct {
	file             *os.File
	fileSize         int64
	eocdOffset       int64
	centralDirOffset int64
	sigBlockOffset   int64
	schemeV2Block    []byte
	eocd             []byte
}

type schemeV2NotFoundError struct {
	err error
}

func (e *schemeV2NotFoundError) Error() string {
	return "Scheme V2 signature not found: " + e.err.Error()
}

func isSchemeV2NotFoundError(err error) bool {
	_, ok := err.(*schemeV2NotFoundError)
	return ok
}

func verifySchemeV2(path string) ([][]*x509.Certificate, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	s := schemeV2{
		file:     f,
		fileSize: fi.Size(),
	}

	if err := s.findEocd(); err != nil {
		return nil, &schemeV2NotFoundError{err}
	}

	if s.isZip64() {
		return nil, &schemeV2NotFoundError{errors.New("ZIP64 APK not supported")}
	}

	var sigBlock []byte
	sigBlock, s.sigBlockOffset, err = s.findApkSigningBlock()
	if err != nil {
		return nil, &schemeV2NotFoundError{err}
	}

	if err := s.findSignatureSchemeV2Block(sigBlock); err != nil {
		return nil, &schemeV2NotFoundError{err}
	}

	certChain, err := s.verify()
	if err != nil {
		return nil, err
	}

	return certChain, nil
}

func (s *schemeV2) findEocd() error {
	if s.fileSize < eocdRecMinSize {
		return fmt.Errorf("APK file is too short (%d bytes).", s.fileSize)
	}

	if err := s.findEocdMaxCommentSize(0); err == nil {
		return nil
	}
	return s.findEocdMaxCommentSize(math.MaxUint16)
}

func (s *schemeV2) findEocdMaxCommentSize(maxCommentSize int) error {
	maxCommentSize = cutils.MinInt(maxCommentSize, int(s.fileSize-eocdRecMinSize))

	buf := make([]byte, eocdRecMinSize+maxCommentSize)
	bufOffsetInFile := s.fileSize - int64(len(buf))

	if _, err := s.file.Seek(bufOffsetInFile, io.SeekStart); err != nil {
		return err
	}

	if _, err := io.ReadFull(s.file, buf); err != nil {
		return err
	}

	maxCommentSize = cutils.MinInt(len(buf)-eocdRecMinSize, math.MaxUint16)
	emptyCommentStart := len(buf) - eocdRecMinSize

	for commentSize := 0; commentSize < maxCommentSize; commentSize++ {
		pos := emptyCommentStart - commentSize
		if binary.LittleEndian.Uint32(buf[pos:pos+4]) == eocdRecMagic {
			recordCommentSize := binary.LittleEndian.Uint16(buf[pos+eocdCommentSizeOffset:])
			if int(recordCommentSize) == commentSize {
				s.eocdOffset = bufOffsetInFile + int64(pos)
				s.centralDirOffset = int64(binary.LittleEndian.Uint32(buf[pos+eocdCentralDirOffsetOffset:]))
				s.eocd = buf[pos:]

				if s.centralDirOffset >= s.eocdOffset {
					return fmt.Errorf("ZIP Central Directory offset ouf of range: %d. Zip End of Central Directory offset: %d",
						s.centralDirOffset, s.eocdOffset)
				}

				centralDirSize := binary.LittleEndian.Uint32(buf[pos+eocdCentralDirSizeOffset:])
				if s.centralDirOffset+int64(centralDirSize) != s.eocdOffset {
					return errors.New("ZIP Central Directory is not immediately followed by End of Central Directory")
				}
				return nil
			}
		}
	}
	return errEocdNotFound
}

func (s *schemeV2) isZip64() bool {
	locatorPos := s.eocdOffset - zip64LocatorSize
	if locatorPos < 0 {
		return false
	}

	if _, err := s.file.Seek(locatorPos, io.SeekStart); err != nil {
		return false
	}

	var magic uint32
	if err := binary.Read(s.file, binary.LittleEndian, &magic); err != nil {
		return false
	}
	return magic == zip64LocatorMagic
}

func (s *schemeV2) findApkSigningBlock() (block []byte, offset int64, err error) {
	if s.centralDirOffset < apkSigBlockMinSize {
		err = errNoV2Signature
		return
	}

	footer := make([]byte, 24)

	if _, err = s.file.Seek(s.centralDirOffset-int64(len(footer)), io.SeekStart); err != nil {
		return
	}

	if _, err = io.ReadFull(s.file, footer); err != nil {
		return
	}

	if binary.LittleEndian.Uint64(footer[8:]) != apkSigBlockMagicLo ||
		binary.LittleEndian.Uint64(footer[16:]) != apkSigBlockMagicHi {
		err = errNoV2Signature
		return
	}

	blockSizeFooter := binary.LittleEndian.Uint64(footer)
	if blockSizeFooter < uint64(len(footer)) || blockSizeFooter > math.MaxInt32-8 {
		err = fmt.Errorf("APK Signing Block size out of range: %d", blockSizeFooter)
		return
	}

	totalSize := int64(blockSizeFooter + 8)
	if totalSize < apkSigBlockMinSize {
		err = fmt.Errorf("Apk Signing Block is too small: %d vs %d", totalSize, apkSigBlockMinSize)
		return
	}

	offset = int64(s.centralDirOffset) - totalSize
	if offset < 0 {
		err = fmt.Errorf("APK Signing Block offset out of range: %d", offset)
		return
	}

	block = make([]byte, totalSize)
	if _, err = s.file.Seek(offset, io.SeekStart); err != nil {
		return
	}

	if _, err = io.ReadFull(s.file, block); err != nil {
		return
	}

	if blockSizeHeader := binary.LittleEndian.Uint64(block); blockSizeHeader != blockSizeFooter {
		err = fmt.Errorf("APK Signing Block sizes in header and footer do not match: %d vs %d",
			blockSizeHeader, blockSizeFooter)
		return
	}

	return
}

func (s *schemeV2) findSignatureSchemeV2Block(sigBlock []byte) error {
	pairs := bytes.NewReader(sigBlock[8 : len(sigBlock)-24])
	entryCount := 0
	for pairs.Len() > 0 {
		entryCount++

		if pairs.Len() < 8 {
			return fmt.Errorf("Insufficient data to read size of APK Signing Block entry #%d", entryCount)
		}

		var entryLen int64
		binary.Read(pairs, binary.LittleEndian, &entryLen)
		if entryLen < 4 || entryLen > math.MaxInt32 {
			return fmt.Errorf("APK Signing Block entry #%d size out of range: %d", entryCount, entryLen)
		}

		nextEntryPos := pairs.Size() - int64(pairs.Len()) + entryLen
		if entryLen > int64(pairs.Len()) {
			return fmt.Errorf("APK Signing Block entry #%d size out of range: %d, available: %d",
				entryCount, entryLen, pairs.Len())
		}

		var id int32
		binary.Read(pairs, binary.LittleEndian, &id)
		if id == apkSignatureSchemeV2BlockId {
			s.schemeV2Block = make([]byte, entryLen-4)
			if _, err := pairs.Read(s.schemeV2Block); err != nil {
				return err
			}
			return nil
		}

		pairs.Seek(nextEntryPos, io.SeekStart)
	}

	return errors.New("No APK Signature Scheme v2 block in APK Signing Block")
}

func (s *schemeV2) getLenghtPrefixedSlice(r *bytes.Buffer) (*bytes.Buffer, error) {
	if r.Len() < 4 {
		return nil, fmt.Errorf("Remaining buffer too short to contain length of length-prefixed field. Remaining: %d", r.Len())
	}

	var length int32
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return nil, err
	}

	if length < 0 {
		return nil, errors.New("Negative length")
	} else if int(length) > r.Len() {
		return nil, fmt.Errorf("Length-prefixed field longer than remaining buffer. "+
			"Field length: %d, remaining: %d", length, r.Len())
	}
	return bytes.NewBuffer(r.Next(int(length))), nil
}

func (s *schemeV2) verify() ([][]*x509.Certificate, error) {
	signerCount := 0
	contentDigests := make(map[crypto.Hash][]byte)
	var signerCerts [][]*x509.Certificate

	signatureBlock := bytes.NewBuffer(s.schemeV2Block)

	signers, err := s.getLenghtPrefixedSlice(signatureBlock)
	if err != nil {
		return nil, fmt.Errorf("Failed to read list of signers: %s", err.Error())
	}

	for signers.Len() > 0 {
		signerCount++

		signer, err := s.getLenghtPrefixedSlice(signers)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse/verify signer #%d block: %s", signerCount, err.Error())
		}

		certs, err := s.verifySigner(signer, contentDigests)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse/verify signer #%d block: %s", signerCount, err.Error())
		}

		signerCerts = append(signerCerts, certs)
	}

	if len(signerCerts) == 0 {
		return nil, errors.New("No signers found.")
	}

	if len(contentDigests) == 0 {
		return nil, errors.New("No content digests found.")
	}

	if err := s.verifyIntegrity(contentDigests); err != nil {
		return nil, fmt.Errorf("Failed to verify integrity: %s", err.Error())
	}

	return signerCerts, nil
}

func (s *schemeV2) verifySigner(signerBlock *bytes.Buffer, contentDigests map[crypto.Hash][]byte) ([]*x509.Certificate, error) {
	signedData, err := s.getLenghtPrefixedSlice(signerBlock)
	if err != nil {
		return nil, fmt.Errorf("Failed to read signed data: %s", err.Error())
	}
	signedDataBytes := signedData.Bytes()

	signatures, err := s.getLenghtPrefixedSlice(signerBlock)
	if err != nil {
		return nil, fmt.Errorf("Failed to read signatures: %s", err.Error())
	}

	publicKeyBytes, err := s.getLenghtPrefixedSlice(signerBlock)
	if err != nil {
		return nil, fmt.Errorf("Failed to read publicKeyBytes: %s", err.Error())
	}

	signatureCount := 0
	bestAlgo := int32(-1)
	var bestAlgoSignature []byte
	var signaturesAlgos []int32

	for signatures.Len() > 0 {
		signatureCount++

		signature, err := s.getLenghtPrefixedSlice(signatures)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse signature record #%d: %s", signatureCount, err.Error())
		}

		if signature.Len() < 8 {
			return nil, fmt.Errorf("Signature record %d is too short", signatureCount)
		}

		var algo int32
		if err := binary.Read(signature, binary.LittleEndian, &algo); err != nil {
			return nil, fmt.Errorf("Failed to parse signature record #%d: %s", signatureCount, err.Error())
		}

		signaturesAlgos = append(signaturesAlgos, algo)
		if !s.isSupportedAlgorithm(algo) {
			continue
		}

		if bestAlgo == -1 || s.compareAlgos(algo, bestAlgo) > 0 {
			bestAlgo = algo
			sigBytes, err := s.getLenghtPrefixedSlice(signature)
			if err != nil {
				return nil, fmt.Errorf("Failed to read signature bytes from signature record #%d: %s", signatureCount, err.Error())
			}
			bestAlgoSignature = sigBytes.Bytes()
		}
	}

	if bestAlgo == -1 {
		if signatureCount == 0 {
			return nil, errors.New("No signatures found.")
		} else {
			return nil, errors.New("No supported signatures found.")
		}
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes.Bytes())
	if err != nil {
		return nil, fmt.Errorf("Failed to parse public key: %s", err.Error())
	}

	switch bestAlgo {
	case sigRsaPssWithSha256:
		hashed := sha256.Sum256(signedDataBytes)
		err = rsa.VerifyPSS(publicKey.(*rsa.PublicKey), crypto.SHA256, hashed[:], bestAlgoSignature, &rsa.PSSOptions{
			SaltLength: 256 / 8,
		})
		if err != nil { // FIXME: not tested
			panic(fmt.Sprintf("verification failed on untested algo: %s", err.Error()))
		}
	case sigRsaPssWithSha512:
		hashed := sha512.Sum512(signedDataBytes)
		err = rsa.VerifyPSS(publicKey.(*rsa.PublicKey), crypto.SHA512, hashed[:], bestAlgoSignature, &rsa.PSSOptions{
			SaltLength: 512 / 8,
		})
		if err != nil { // FIXME: not tested
			panic(fmt.Sprintf("verification failed on untested algo: %s", err.Error()))
		}
	case sigRsaPkcs1V15WithSha256:
		hashed := sha256.Sum256(signedDataBytes)
		err = rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.SHA256, hashed[:], bestAlgoSignature)
	case sigRsaPkcs1V15WithSha512:
		hashed := sha512.Sum512(signedDataBytes)
		err = rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.SHA512, hashed[:], bestAlgoSignature)
	case sigEcdsaWithSha256, sigEcdsaWithSha512, sigDsaWithSha256:
		var params []*big.Int
		if _, err := asn1.Unmarshal(bestAlgoSignature, &params); err != nil {
			return nil, fmt.Errorf("Failed to unmarshal ECDSA signature: %s", err.Error())
		}

		var hashed []byte
		if bestAlgo == sigEcdsaWithSha256 || bestAlgo == sigDsaWithSha256 {
			h := sha256.Sum256(signedDataBytes)
			hashed = h[:]
		} else {
			h := sha512.Sum512(signedDataBytes)
			hashed = h[:]
		}

		if bestAlgo == sigDsaWithSha256 {
			k := publicKey.(*dsa.PublicKey)
			hashed = hashed[:k.Q.BitLen()/8]
			if !dsa.Verify(k, hashed, params[0], params[1]) {
				err = errors.New("DSA verification failed.")
			}
		} else {
			if !ecdsa.Verify(publicKey.(*ecdsa.PublicKey), hashed, params[0], params[1]) {
				err = errors.New("ECDSA verification failed.")
			}
		}
	default:
		err = errors.New("unhandled signature type")
	}

	if err != nil {
		return nil, fmt.Errorf("Failed to verify signature of type 0x%x: %s", bestAlgo, err.Error())
	}

	var contentDigest []byte
	var digestSigAlgorithms []int32
	digests, err := s.getLenghtPrefixedSlice(signedData)
	if err != nil {
		return nil, fmt.Errorf("Failed to read digests from signedData: %s", err.Error())
	}

	digestCount := 0
	for digests.Len() > 0 {
		digestCount++

		digest, err := s.getLenghtPrefixedSlice(digests)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse digest #%d: %s", digestCount, err.Error())
		} else if digest.Len() < 8 {
			return nil, fmt.Errorf("Failed to parse digest #%d: record too short", digestCount)
		}

		var sigAlgorithm int32
		binary.Read(digest, binary.LittleEndian, &sigAlgorithm)
		digestSigAlgorithms = append(digestSigAlgorithms, sigAlgorithm)
		if sigAlgorithm == bestAlgo {
			cd, err := s.getLenghtPrefixedSlice(digest)
			if err != nil {
				return nil, fmt.Errorf("Failed to read content digest for digest #%d: %s", digestCount, err.Error())
			}
			contentDigest = cd.Bytes()
		}
	}

	algosEqual := len(digestSigAlgorithms) == len(signaturesAlgos)
	for i := 0; algosEqual && i < len(digestSigAlgorithms); i++ {
		algosEqual = digestSigAlgorithms[i] == signaturesAlgos[i]
	}

	if !algosEqual {
		return nil, errors.New("Signature algorithms don't match between digests and signatures records")
	}

	digestAlgorithm := s.getDigestTypeForAlgo(bestAlgo)
	previousSignerDigest := contentDigests[digestAlgorithm]
	contentDigests[digestAlgorithm] = contentDigest
	if previousSignerDigest != nil && !bytes.Equal(previousSignerDigest, contentDigest) {
		return nil, fmt.Errorf("0x%x contents digest does not match the digest specified by a preceding signer", digestAlgorithm)
	}

	certificates, err := s.getLenghtPrefixedSlice(signedData)
	if err != nil {
		return nil, fmt.Errorf("Failed to read certificates from signedData: %s", err.Error())
	}

	var certs []*x509.Certificate
	certificateCount := 0
	for certificates.Len() > 0 {
		certificateCount++
		encodedCert, err := s.getLenghtPrefixedSlice(certificates)
		if err != nil {
			return nil, fmt.Errorf("Failed to read certificate #%d: %s", certificateCount, err.Error())
		}

		cert, err := x509.ParseCertificate(encodedCert.Bytes())
		if err != nil {
			return nil, fmt.Errorf("Failed to parse certificate #%d: %s", certificateCount, err.Error())
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.New("No certificates listed.")
	}

	if !bytes.Equal(certs[0].RawSubjectPublicKeyInfo, publicKeyBytes.Bytes()) {
		return nil, errors.New("Public key mismatch between certificate and signature record")
	}

	return certs, nil
}

func (s *schemeV2) isSupportedAlgorithm(algo int32) bool {
	switch algo {
	case sigRsaPssWithSha256, sigRsaPssWithSha512,
		sigRsaPkcs1V15WithSha256, sigRsaPkcs1V15WithSha512,
		sigEcdsaWithSha256, sigEcdsaWithSha512,
		sigDsaWithSha256:
		return true
	default:
		return false
	}
}

func (s *schemeV2) getDigestTypeForAlgo(algo int32) crypto.Hash {
	switch algo {
	case sigRsaPssWithSha256, sigRsaPkcs1V15WithSha256, sigEcdsaWithSha256, sigDsaWithSha256:
		return crypto.SHA256
	case sigRsaPssWithSha512, sigRsaPkcs1V15WithSha512, sigEcdsaWithSha512:
		return crypto.SHA512
	default:
		panic(fmt.Sprintf("Unknown signature algorithm 0x%x", algo))
	}
}

func (s *schemeV2) compareAlgos(a, b int32) int {
	digest1 := s.getDigestTypeForAlgo(a)
	digest2 := s.getDigestTypeForAlgo(b)

	switch digest1 {
	case crypto.SHA256:
		switch digest2 {
		case crypto.SHA256:
			return 0
		case crypto.SHA512:
			return -1
		default:
			panic(fmt.Sprintf("Unknown digest2: %d", digest2))
		}
	case crypto.SHA512:
		switch digest2 {
		case crypto.SHA256:
			return 1
		case crypto.SHA512:
			return 0
		default:
			panic(fmt.Sprintf("Unknown digest2: %d", digest2))
		}
	default:
		panic(fmt.Sprintf("Unknown digest1: %d", digest1))
	}
}

func (s *schemeV2) verifyIntegrity(expectedDigests map[crypto.Hash][]byte) error {
	beforeApkSigningBlock := &dataSourceApk{file: s.file, start: 0, end: s.sigBlockOffset}
	centralDir := &dataSourceApk{file: s.file, start: s.centralDirOffset, end: s.eocdOffset}
	eocd := &dataSourceEocd{eocd: append([]byte(nil), s.eocd...)}

	// For the purposes of integrity verification, ZIP End of Central Directory's field Start of
	// Central Directory must be considered to point to the offset of the APK Signing Block.
	binary.LittleEndian.PutUint32(eocd.eocd[eocdCentralDirOffsetOffset:], uint32(s.sigBlockOffset))

	digestAlgorithms := make([]crypto.Hash, 0, len(expectedDigests))
	for algo := range expectedDigests {
		digestAlgorithms = append(digestAlgorithms, algo)
	}

	actualDigests, err := s.computeContentDigests(digestAlgorithms, beforeApkSigningBlock, centralDir, eocd)
	if err != nil {
		return fmt.Errorf("Failed to compute digest(s) of contents: %s", err.Error())
	}

	for i, algo := range digestAlgorithms {
		if !bytes.Equal(expectedDigests[algo], actualDigests[i]) {
			return fmt.Errorf("%T digest of contents did not verify.", algo.New())
		}
	}
	return nil
}

func (s *schemeV2) computeContentDigests(digestAlgorithms []crypto.Hash, contents ...dataSource) ([][]byte, error) {
	var totalChunkCount int64
	for _, input := range contents {
		totalChunkCount += input.chunkCount()
	}

	if totalChunkCount >= math.MaxInt32/1024 {
		return nil, fmt.Errorf("Too many chunks: %d", totalChunkCount)
	}

	digestsOfChunks := make([][]byte, len(digestAlgorithms))
	hashers := make([]hash.Hash, len(digestAlgorithms))
	for i, algo := range digestAlgorithms {
		buf := make([]byte, 5+totalChunkCount*int64(algo.Size()))
		buf[0] = 0x5a
		binary.LittleEndian.PutUint32(buf[1:], uint32(totalChunkCount))

		digestsOfChunks[i] = buf
		hashers[i] = algo.New()
	}

	chunkContentPrefix := make([]byte, 5)
	chunkContentPrefix[0] = 0xa5

	chunkIndex := 0
	for inputIdx, input := range contents {
		var offset int64
		remaining := input.length()
		for remaining > 0 {
			chunkSize := cutils.MinInt64(remaining, chunkSize)
			binary.LittleEndian.PutUint32(chunkContentPrefix[1:], uint32(chunkSize))

			for i := range hashers {
				hashers[i].Write(chunkContentPrefix)

				if err := input.writeTo(hashers[i], offset, chunkSize); err != nil {
					return nil, fmt.Errorf("Failed to digest chunk #%d of section #%d", chunkIndex, inputIdx)
				}

				sum := hashers[i].Sum(nil)
				hashers[i].Reset()

				dest := digestsOfChunks[i][5+chunkIndex*len(sum):]
				for x := range sum {
					dest[x] = sum[x]
				}
			}
			offset += chunkSize
			remaining -= chunkSize
			chunkIndex++
		}
	}
	result := make([][]byte, len(digestAlgorithms))
	for i := range digestsOfChunks {
		hashers[i].Write(digestsOfChunks[i])
		result[i] = hashers[i].Sum(nil)
	}
	return result, nil
}

type dataSource interface {
	chunkCount() int64
	length() int64
	writeTo(w io.Writer, offset, size int64) error
}

type dataSourceApk struct {
	file       *os.File
	start, end int64
}

func (se *dataSourceApk) chunkCount() int64 {
	return (se.end - se.start + chunkSize - 1) / chunkSize
}

func (se *dataSourceApk) writeTo(w io.Writer, offset, size int64) error {
	if offset > se.end || offset > se.end-se.start {
		return errors.New("Out of bounds offset")
	} else if size > se.end-se.start || offset+size > se.end-se.start {
		return errors.New("Out of bounds size")
	}

	if _, err := se.file.Seek(se.start+offset, io.SeekStart); err != nil {
		return err
	}

	_, err := io.CopyN(w, se.file, size)
	return err
}

func (se *dataSourceApk) length() int64 {
	return se.end - se.start
}

type dataSourceEocd struct {
	eocd []byte
}

func (se *dataSourceEocd) chunkCount() int64 {
	return (int64(len(se.eocd)) + chunkSize - 1) / chunkSize
}

func (se *dataSourceEocd) writeTo(w io.Writer, offset, size int64) error {
	if offset >= int64(len(se.eocd)) {
		return errors.New("Out of bounds offset")
	} else if size > int64(len(se.eocd)) || offset+size > int64(len(se.eocd)) {
		return errors.New("Out of bounds size")
	}
	_, err := w.Write(se.eocd[offset : offset+size])
	return err
}

func (se *dataSourceEocd) length() int64 {
	return int64(len(se.eocd))
}
