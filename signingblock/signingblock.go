package signingblock

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
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

	apkSigBlockMinSize = 32
	apkSigBlockMagicHi = 0x3234206b636f6c42
	apkSigBlockMagicLo = 0x20676953204b5041

	blockIdVerityPadding = 0x42726577
	blockIdSchemeV2      = 0x7109871a
	blockIdSchemeV3      = 0xf05368c0

	schemeIdV1 = 1
	schemeIdV2 = 2
	schemeIdV3 = 3

	maxChunkSize = 1024 * 1024

	sdkVersionN = 24
	sdkVersionP = 28
)

var (
	errNoSigningBlockSignature = errors.New("This apk does not have signing block signature")
	errEocdNotFound            = errors.New("EOCD record not found.")
)

type signatureBlockScheme interface {
	parseSigners(block *bytes.Buffer, contentDigests map[crypto.Hash][]byte, result *VerificationResult)
	finalizeResult(minSdkVersion, maxSdkVersion int32, result *VerificationResult)
}

type signingBlock struct {
	file             *os.File
	fileSize         int64
	eocdOffset       int64
	centralDirOffset int64
	sigBlockOffset   int64
	eocd             []byte
}

type signingBlockNotFoundError struct {
	err error
}

func (e *signingBlockNotFoundError) Error() string {
	return "Signature Block signature not found: " + e.err.Error()
}

func IsSigningBlockNotFoundError(err error) bool {
	_, ok := err.(*signingBlockNotFoundError)
	return ok
}

func VerifySigningBlock(path string, minSdkVersion, maxSdkVersion int32) (res *VerificationResult, magic uint32, err error) {
	if maxSdkVersion < sdkVersionN {
		return nil, 0, &signingBlockNotFoundError{errors.New("unsupported SDK version, requires at least N")}
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}

	if fi.Size() < 4 {
		err = fmt.Errorf("APK file is too short (%d bytes).", fi.Size())
		return
	}

	if err = binary.Read(f, binary.LittleEndian, &magic); err != nil {
		err = fmt.Errorf("Failed to read APK magic: %s", err.Error())
		return
	}

	s := signingBlock{
		file:     f,
		fileSize: fi.Size(),
	}

	if err = s.findEocd(); err != nil {
		err = &signingBlockNotFoundError{err}
		return
	}

	if s.isZip64() {
		err = &signingBlockNotFoundError{errors.New("ZIP64 APK not supported")}
		return
	}

	var sigBlock []byte
	sigBlock, s.sigBlockOffset, err = s.findApkSigningBlock()
	if err != nil {
		err = &signingBlockNotFoundError{err}
		return
	}

	schemeId, block, err := s.findSignatureBlocks(sigBlock, maxSdkVersion)
	if err != nil {
		err = &signingBlockNotFoundError{err}
		return
	}

	var scheme signatureBlockScheme
	res = &VerificationResult{
		SchemeId: schemeId,
	}

	switch schemeId {
	case schemeIdV3:
		scheme = &schemeV3{}
	case schemeIdV2:
		scheme = &schemeV2{}
	default:
		panic("unhandled")
	}

	s.verify(scheme, block, minSdkVersion, maxSdkVersion, res)
	err = res.GetLastError()
	return
}

func (s *signingBlock) findEocd() error {
	if s.fileSize < eocdRecMinSize {
		return fmt.Errorf("APK file is too short (%d bytes).", s.fileSize)
	}

	if err := s.findEocdMaxCommentSize(0); err == nil {
		return nil
	}
	return s.findEocdMaxCommentSize(math.MaxUint16)
}

func (s *signingBlock) findEocdMaxCommentSize(maxCommentSize int) error {
	if maxCommentSize > int(s.fileSize-eocdRecMinSize) {
		maxCommentSize = int(s.fileSize - eocdRecMinSize)
	}

	buf := make([]byte, eocdRecMinSize+maxCommentSize)
	bufOffsetInFile := s.fileSize - int64(len(buf))

	if _, err := s.file.Seek(bufOffsetInFile, io.SeekStart); err != nil {
		return err
	}

	if _, err := io.ReadFull(s.file, buf); err != nil {
		return err
	}

	maxCommentSize = len(buf) - eocdRecMinSize
	if maxCommentSize > math.MaxUint16 {
		maxCommentSize = math.MaxUint16
	}
	emptyCommentStart := len(buf) - eocdRecMinSize

	for commentSize := 0; commentSize <= maxCommentSize; commentSize++ {
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

func (s *signingBlock) isZip64() bool {
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

func (s *signingBlock) findApkSigningBlock() (block []byte, offset int64, err error) {
	if s.centralDirOffset < apkSigBlockMinSize {
		err = errNoSigningBlockSignature
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
		err = errNoSigningBlockSignature
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

func (s *signingBlock) findSignatureBlocks(sigBlock []byte, maxSdkVersion int32) (schemeId int, block []byte, err error) {
	pairs := bytes.NewReader(sigBlock[8 : len(sigBlock)-24])
	entryCount := 0

	for pairs.Len() > 0 {
		entryCount++

		if pairs.Len() < 8 {
			err = fmt.Errorf("Insufficient data to read size of APK Signing Block entry #%d", entryCount)
			return
		}

		var entryLen int64
		binary.Read(pairs, binary.LittleEndian, &entryLen)
		if entryLen < 4 || entryLen > math.MaxInt32 {
			err = fmt.Errorf("APK Signing Block entry #%d size out of range: %d", entryCount, entryLen)
			return
		}

		nextEntryPos := pairs.Size() - int64(pairs.Len()) + entryLen
		if entryLen > int64(pairs.Len()) {
			err = fmt.Errorf("APK Signing Block entry #%d size out of range: %d, available: %d",
				entryCount, entryLen, pairs.Len())
			return
		}

		var id uint32
		if err = binary.Read(pairs, binary.LittleEndian, &id); err != nil {
			err = fmt.Errorf("failed to read signing block id: %s", err.Error())
			return
		}

		switch id {
		case blockIdSchemeV3:
			if maxSdkVersion >= sdkVersionP && schemeIdV3 > schemeId {
				block = make([]byte, entryLen-4)
				if _, err = pairs.Read(block); err != nil {
					return
				}
				schemeId = schemeIdV3
			}
		case blockIdSchemeV2:
			if schemeIdV2 > schemeId {
				block = make([]byte, entryLen-4)
				if _, err = pairs.Read(block); err != nil {
					return
				}
				schemeId = schemeIdV2
			}
		case blockIdVerityPadding:
			// TODO: NYI
		}

		if _, err = pairs.Seek(nextEntryPos, io.SeekStart); err != nil {
			return
		}
	}

	if schemeId == 0 {
		err = errors.New("No APK Signature Scheme v2 block in APK Signing Block")
	}
	return
}

func (s *signingBlock) verify(scheme signatureBlockScheme, block []byte, minSdkVersion, maxSdkVersion int32, res *VerificationResult) {
	contentDigests := make(map[crypto.Hash][]byte)
	signatureBlock := bytes.NewBuffer(block)

	scheme.parseSigners(signatureBlock, contentDigests, res)
	if res.ContainsErrors() {
		return
	}

	if len(res.Certs) == 0 {
		res.addError("no signers found")
		return
	}

	if len(contentDigests) == 0 {
		res.addError("no content digests found")
		return
	}

	if !s.verifyIntegrity(contentDigests, res) {
		return
	}

	scheme.finalizeResult(minSdkVersion, maxSdkVersion, res)
}

func (s *signingBlock) verifyIntegrity(expectedDigests map[crypto.Hash][]byte, result *VerificationResult) bool {
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
		result.addError("Failed to compute digest(s) of contents: %s", err.Error())
		return false
	}

	for i, algo := range digestAlgorithms {
		if !bytes.Equal(expectedDigests[algo], actualDigests[i]) {
			result.addError("%T digest of contents did not verify.", algo.New())
			continue

		}
	}
	return true
}

func (s *signingBlock) computeContentDigests(digestAlgorithms []crypto.Hash, contents ...dataSource) ([][]byte, error) {
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
			chunkSize := remaining
			if chunkSize > maxChunkSize {
				chunkSize = maxChunkSize
			}

			binary.LittleEndian.PutUint32(chunkContentPrefix[1:], uint32(chunkSize))

			for i := range hashers {
				hashers[i].Write(chunkContentPrefix)

				if err := input.writeTo(hashers[i], offset, chunkSize); err != nil {
					return nil, fmt.Errorf("Failed to digest chunk #%d of section #%d", chunkIndex, inputIdx)
				}

				sum := hashers[i].Sum(nil)
				hashers[i].Reset()

				copy(digestsOfChunks[i][5+chunkIndex*len(sum):], sum)
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
	return (se.end - se.start + maxChunkSize - 1) / maxChunkSize
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
	return (int64(len(se.eocd)) + maxChunkSize - 1) / maxChunkSize
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
