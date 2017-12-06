package apkverifier

import (
	"github.com/avast/apkparser"
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/fullsailor/pkcs7"
	"hash"
	"io"
	"io/ioutil"
	"math/big"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// These two arrays are synchronized
var (
	digestAlgorithms = [...]string{
		"SHA-512",
		"SHA-384",
		"SHA-256",
		"SHA1",
	}
	digestHashers = [...]func() hash.Hash{
		sha512.New,
		sha512.New384,
		sha256.New,
		sha1.New,
	}
)

var oidToAlgo = map[string]x509.SignatureAlgorithm{
	" 1.2.840.113549.1.1.2":              x509.MD2WithRSA,
	"1.3.14.3.2.24 1.2.840.113549.1.1.2": x509.MD2WithRSA,

	" 1.2.840.113549.1.1.4":                   x509.MD5WithRSA,
	"1.3.14.3.2.25 1.2.840.113549.1.1.4":      x509.MD5WithRSA,
	"1.3.14.3.2.3 1.2.840.113549.1.1.4":       x509.MD5WithRSA,
	"1.2.840.113549.2.5 1.2.840.113549.1.1.1": x509.MD5WithRSA,

	" 1.2.840.113549.1.1.5":              x509.SHA1WithRSA,
	"1.3.14.3.2.26 1.2.840.113549.1.1.1": x509.SHA1WithRSA,
	"1.3.14.3.2.29 1.2.840.113549.1.1.1": x509.SHA1WithRSA,

	"2.16.840.1.101.3.4.2.1 1.2.840.113549.1.1.1":  x509.SHA256WithRSA,
	"2.16.840.1.101.3.4.2.1 1.2.840.113549.1.1.11": x509.SHA256WithRSA,
	"2.16.840.1.101.3.4.2.2 1.2.840.113549.1.1.1":  x509.SHA384WithRSA,
	"2.16.840.1.101.3.4.2.3 1.2.840.113549.1.1.1":  x509.SHA512WithRSA,

	"1.3.14.3.2.26 1.2.840.10040.4.1": x509.DSAWithSHA1,
	" 1.2.840.10040.4.3":              x509.DSAWithSHA1,
	"1.3.14.3.2.26 1.2.840.10040.4.3": x509.DSAWithSHA1,

	"2.16.840.1.101.3.4.2.1 1.2.840.10040.4.1":      x509.DSAWithSHA256,
	"2.16.840.1.101.3.4.2.1 2.16.840.1.101.3.4.3.2": x509.DSAWithSHA256,

	"2.16.840.1.101.3.4.2.1 1.2.840.10045.2.1": x509.ECDSAWithSHA256,
	"2.16.840.1.101.3.4.2.2 1.2.840.10045.2.1": x509.ECDSAWithSHA384,
	"2.16.840.1.101.3.4.2.3 1.2.840.10045.2.1": x509.ECDSAWithSHA512,
}

var errNoKnownHashes = errors.New("No known hashes")

type schemeV1Signature struct {
	sigBlockFilename  string
	cert              *pkcs7.PKCS7
	signatureManifest *manifest
	chain             []*x509.Certificate
}

type schemeV1 struct {
	sigs     map[string]*schemeV1Signature
	manifest *manifest
	hashers  []hash.Hash
	chain    [][]*x509.Certificate
}

func verifySchemeV1(apk *apkparser.ZipReader) ([][]*x509.Certificate, error) {
	scheme := schemeV1{
		sigs:    make(map[string]*schemeV1Signature),
		hashers: make([]hash.Hash, len(digestHashers)),
	}

	const prefix = "META-INF/"
	var errors []string
	for path, f := range apk.File {
		upath := strings.ToUpper(path)
		if !strings.HasPrefix(upath, prefix) {
			continue
		}

		switch {
		case upath == "META-INF/MANIFEST.MF":
			if err := scheme.addManifest(f); err != nil {
				errors = append(errors, err.Error())
			}
		case strings.HasSuffix(upath, ".RSA") || strings.HasSuffix(upath, ".DSA") || strings.HasSuffix(upath, ".EC"):
			if err := scheme.addSignatureBlock(upath, f); err != nil {
				errors = append(errors, err.Error())
			}
		case strings.HasSuffix(upath, ".SF"):
			if err := scheme.addSignatureFile(upath, f); err != nil {
				errors = append(errors, err.Error())
			}
		}
	}

	if err := scheme.prepForVerification(); err != nil {
		return scheme.chain, fmt.Errorf("Can't verify: %s (%s)", err.Error(), strings.Join(errors, ";"))
	}

	err := scheme.verify(apk)
	return scheme.chain, err
}

func (p *schemeV1) addManifest(f *apkparser.ZipReaderFile) (err error) {
	if p.manifest != nil {
		return fmt.Errorf("Manifest already parsed!")
	}

	p.manifest, err = parseManifest(f, true)
	return
}

func (p *schemeV1) addSignatureFile(pathUpper string, f *apkparser.ZipReaderFile) (err error) {
	prefix := p.signaturePrefix(pathUpper)
	s := p.sigs[prefix]
	if s == nil {
		s = &schemeV1Signature{}
		p.sigs[prefix] = s
	}

	s.signatureManifest, err = parseManifest(f, false)
	return
}

func (p *schemeV1) addSignatureBlock(pathUpper string, f *apkparser.ZipReaderFile) error {
	if err := f.Open(); err != nil {
		return err
	}
	defer f.Close()

	var err error
	var raw []byte
	var sig *pkcs7.PKCS7
	for f.Next() {
		raw, err = ioutil.ReadAll(f)
		if err != nil {
			continue
		}

		sig, err = pkcs7.Parse(raw)
		if err != nil {
			continue
		}

		prefix := p.signaturePrefix(pathUpper)
		s := p.sigs[prefix]
		if s == nil {
			s = &schemeV1Signature{}
			p.sigs[prefix] = s
		}
		s.sigBlockFilename = f.Name
		s.cert = sig

		return nil
	}

	return fmt.Errorf("Failed to open %s: %v", f.Name, err)
}

func (p *schemeV1) signaturePrefix(pathUpper string) string {
	fn := filepath.Base(pathUpper)
	idx := strings.LastIndexByte(fn, '.')
	return fn[:idx]
}

func (p *schemeV1) prepForVerification() error {
	if p.manifest == nil {
		return errors.New("No valid MANIFEST.SF")
	}

	for prefix, sig := range p.sigs {
		if sig.cert == nil || sig.signatureManifest == nil {
			delete(p.sigs, prefix)
		}
	}

	if len(p.sigs) == 0 {
		return errors.New("No signatures.")
	}

	return nil
}

func (p *schemeV1) verify(apk *apkparser.ZipReader) error {
	var err error
	validSignatures := map[string]*schemeV1Signature{}
	var lastChain []*x509.Certificate
	for sigName, sig := range p.sigs {
		sig.chain, err = p.verifySignature(sig)
		if err != nil {
			lastChain = sig.chain
			continue
		}

		lastChain = nil
		p.chain = append(p.chain, sig.chain)

		sm := sig.signatureManifest
		if idList, prs := sm.main[attrAndroidApkSigned]; prs {
			tokens := strings.Split(idList, ",")
			for _, tok := range tokens {
				tok = strings.TrimSpace(tok)
				if tok == "" {
					continue
				}

				id, err := strconv.ParseInt(tok, 10, 32)
				if err != nil {
					continue
				}

				if id == 2 {
					return fmt.Errorf("This apk has '%s: %s', cannot be verified using v1 scheme, downgrade attack?",
						attrAndroidApkSigned, idList)
				}
			}
		}

		if _, prs := sm.main[attrSignatureVersion]; !prs {
			continue
		}

		createdBySigntool := strings.Contains(sm.main[attrCreatedBy], "signtool")

		if sm.mainAttributtesEnd > 0 && !createdBySigntool {
			err = p.verifyManifestEntry(sm.main, attrDigestMainAttrSuffix, func(hash []byte, hasher hash.Hash) error {
				hasher.Write(p.manifest.rawData[:p.manifest.mainAttributtesEnd])
				if !bytes.Equal(hash, hasher.Sum(nil)) {
					return errors.New("Invalid manifest main attributes hash!")
				}
				return nil
			})

			if err != nil && err != errNoKnownHashes {
				continue
			}
		}

		suffix := attrDigestSigntoolSuffix
		if createdBySigntool {
			suffix = attrDigestSuffix
		}

		err = p.verifyManifestEntry(sm.main, suffix, func(hash []byte, hasher hash.Hash) error {
			if hasher.Write(p.manifest.rawData); !bytes.Equal(hash, hasher.Sum(nil)) {
				return errors.New("Invalid whole manifest hash!")
			}
			return nil
		})

		// file entries only checked if the whole-manifest fails/is not present
		if err != nil {
			for name, attrs := range sm.entries {
				err = p.verifyManifestEntry(attrs, attrDigestSuffix, func(hash []byte, hasher hash.Hash) error {
					data, prs := p.manifest.chunks[name]
					if !prs {
						return fmt.Errorf("Signature entry %s not in manifest.mf file.", name)
					}

					if createdBySigntool && bytes.HasSuffix(data, []byte{'\n', '\n'}) {
						hasher.Write(data[:len(data)-1])
					} else {
						hasher.Write(data)
					}

					if !bytes.Equal(hash, hasher.Sum(nil)) {
						return fmt.Errorf("Invalid hash of manifest entry for %s", name)
					}
					return nil
				})

				if err != nil {
					break
				}
			}
		}

		if err == nil {
			validSignatures[sigName] = sig
		}
	}

	p.sigs = validSignatures

	if len(validSignatures) == 0 {
		if lastChain != nil {
			p.chain = append(p.chain, lastChain)
		}
		return fmt.Errorf("No valid cert chains found, last error: %v", err)
	}

	return p.verifyMainManifest(apk)
}

func (p *schemeV1) verifyMainManifest(apk *apkparser.ZipReader) error {
	for path := range p.manifest.entries {
		if _, prs := apk.File[path]; !prs {
			return fmt.Errorf("Manifest entry '%s' does not exists.", path)
		}
	}

	required := make([]string, 1, len(apk.File))
	required[0] = "AndroidManifest.xml"
	for path, zf := range apk.File {
		if !zf.IsDir && path != "AndroidManifest.xml" && !strings.HasPrefix(path, "META-INF/") {
			required = append(required, path)
		}
	}

	chainsSet := false
	for _, path := range required {
		attrs, prs := p.manifest.entries[path]
		if !prs {
			return fmt.Errorf("No manifest entry for required file '%s'", path)
		}

		err := p.verifyManifestEntry(attrs, attrDigestSuffix, func(hash []byte, hasher hash.Hash) error {
			return p.verifyFileHash(apk.File[path], hash, hasher)
		})
		if err != nil {
			return err
		}

		var certChains [][]*x509.Certificate
		var certFiles []string
		for _, sig := range p.sigs {
			if _, prs := sig.signatureManifest.entries[path]; prs {
				certFiles = append(certFiles, sig.sigBlockFilename)
				certChains = append(certChains, sig.chain)
			}
		}

		if len(certChains) == 0 {
			return fmt.Errorf("File '%s' is not in any signature manifests", path)
		}

		if !chainsSet {
			p.chain = certChains
			chainsSet = true
		} else if !p.certChainsMatch(p.chain, certChains) {
			return fmt.Errorf("Mismatched certificates at entry '%s'", path)
		}
	}
	return nil
}

func (p *schemeV1) certChainsMatch(a, b [][]*x509.Certificate) bool {
	if len(a) != len(b) {
		return false
	}

	for _, ca := range a {
		found := false
		for _, cb := range b {
			if p.chainEqual(ca, cb) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	for _, cb := range b {
		found := false
		for _, ca := range a {
			if p.chainEqual(ca, cb) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (p *schemeV1) chainEqual(a, b []*x509.Certificate) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

func (p *schemeV1) verifyManifestEntry(entry map[string]string, digestSuffix string, verify func(hash []byte, hasher hash.Hash) error) error {
	var hash64 string
	var algoIdx int
	for i, algo := range digestAlgorithms {
		if hash64 = entry[algo+digestSuffix]; hash64 != "" {
			algoIdx = i
			break
		}
	}

	if hash64 == "" {
		return errNoKnownHashes
	}

	hash, err := base64.StdEncoding.DecodeString(hash64)
	if err != nil {
		return fmt.Errorf("Can't decode hash: %s", err.Error())
	}

	if p.hashers[algoIdx] == nil {
		p.hashers[algoIdx] = digestHashers[algoIdx]()
	}
	p.hashers[algoIdx].Reset()

	return verify(hash, p.hashers[algoIdx])
}

func (p *schemeV1) verifyFileHash(f *apkparser.ZipReaderFile, hash []byte, hasher hash.Hash) error {
	if err := f.Open(); err != nil {
		return fmt.Errorf("Can't generate hashes for '%s': %s", f.Name, err.Error())
	}
	defer f.Close()

	for f.Next() {
		hasher.Reset()
		if _, err := io.Copy(hasher, f); err == nil {
			if bytes.Equal(hasher.Sum(nil), hash) {
				return nil
			}
		}
	}

	return fmt.Errorf("No matching hash for '%s'!", f.Name)
}

func (p *schemeV1) verifySignature(sig *schemeV1Signature) ([]*x509.Certificate, error) {
	if len(sig.cert.Signers) == 0 {
		return nil, errors.New("Empty signers slice!")
	}

	info := &sig.cert.Signers[0]
	var issuerSeq pkix.RDNSequence
	if _, err := asn1.Unmarshal(info.IssuerAndSerialNumber.IssuerName.FullBytes, &issuerSeq); err != nil {
		return nil, err
	}
	var issuer pkix.Name
	issuer.FillFromRDNSequence(&issuerSeq)
	issuerCanonical := p.pkixCanonical(&issuer)

	snum := info.IssuerAndSerialNumber.SerialNumber
	signerCertIndex := -1
	for i, crt := range sig.cert.Certificates {
		if snum.Cmp(crt.SerialNumber) == 0 && issuerCanonical == p.pkixCanonical(&crt.Issuer) {
			signerCertIndex = i
			break
		}
	}

	if signerCertIndex == -1 {
		return nil, errors.New("No issuer certificate found")
	}

	signerCert := sig.cert.Certificates[signerCertIndex]
	chain := []*x509.Certificate{signerCert}

	if len(signerCert.UnhandledCriticalExtensions) != 0 {
		return chain, errors.New("Certificate has unhandled critical extensions.")
	}

	da := info.DigestAlgorithm.Algorithm.String()
	dea := info.DigestEncryptionAlgorithm.Algorithm.String()
	algo, prs := oidToAlgo[fmt.Sprintf("%s %s", da, dea)]
	if !prs {
		panic(fmt.Sprintf("Unknown digest algorithm: '%s %s'", da, dea))
	}

	err := p.checkSignature(signerCert, algo, sig.signatureManifest.rawData, info.EncryptedDigest)
	if err != nil {
		return chain, err
	}

	// load cert chain if not self-signed
	if p.pkixCanonical(&signerCert.Issuer) == p.pkixCanonical(&signerCert.Subject) {
		return chain, nil
	}

	issuerCanonical = p.pkixCanonical(&signerCert.Issuer)
	for {
		var issuerCert *x509.Certificate
		for _, crt := range sig.cert.Certificates {
			if issuerCanonical == p.pkixCanonical(&crt.Subject) {
				issuerCert = crt
				break
			}
		}

		if issuerCert == nil {
			break
		}

		chain = append(chain, issuerCert)
		if len(chain) > len(sig.cert.Certificates) {
			break
		}

		issuerCanonical = p.pkixCanonical(&issuerCert.Issuer)
		if issuerCanonical == p.pkixCanonical(&issuerCert.Subject) {
			break
		}
	}

	return chain, nil
}

type dsaSignature struct {
	R, S *big.Int
}

func (p *schemeV1) checkSignature(cert *x509.Certificate, algo x509.SignatureAlgorithm, signed, signature []byte) error {
	switch algo {
	case x509.MD5WithRSA:
		digest := md5.Sum(signed)
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("Unexpected public key type (%T)!", cert.PublicKey)
		}
		return rsa.VerifyPKCS1v15(pub, crypto.MD5, digest[:], signature)
	case x509.DSAWithSHA256:
		hash := sha256.Sum256(signed)
		pub := cert.PublicKey.(*dsa.PublicKey)
		reqLen := pub.Q.BitLen() / 8
		if reqLen > len(hash) {
			return fmt.Errorf("Digest algorithm is too short for given DSA parameters.")
		}
		digest := hash[:reqLen]

		dsaSig := new(dsaSignature)
		if rest, err := asn1.Unmarshal(signature, dsaSig); err != nil {
			return err
		} else if len(rest) != 0 {
			return errors.New("x509: trailing data after DSA signature")
		}
		if dsaSig.R.Sign() <= 0 || dsaSig.S.Sign() <= 0 {
			return errors.New("x509: DSA signature contained zero or negative values")
		}
		if !dsa.Verify(pub, digest, dsaSig.R, dsaSig.S) {
			return errors.New("x509: DSA verification failure")
		}
		return nil
	default:
		return cert.CheckSignature(algo, signed, signature)
	}
}

type byX501Canonical []pkix.AttributeTypeAndValue

func (a byX501Canonical) Len() int      { return len(a) }
func (a byX501Canonical) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a byX501Canonical) Less(i, j int) bool {
	ioid1 := a[i].Type
	ioid2 := a[j].Type
	min := len(ioid1)
	if len(ioid2) < min {
		min = len(ioid2)
	}
	for x := 0; x < min; x++ {
		if ioid1[x] < ioid2[x] {
			return true
		} else if ioid1[x] > ioid2[x] {
			return false
		}

		if (x+1) == len(ioid1) && (x+1) < len(ioid2) {
			return true
		} else if (x+1) < len(ioid1) && (x+1) == len(ioid2) {
			return false
		}
	}
	return false
}

func (p *schemeV1) pkixCanonical(n *pkix.Name) string {
	return p.pkixCanonicalSeq(n.ToRDNSequence())
}

func (p *schemeV1) pkixCanonicalSeq(n pkix.RDNSequence) string {
	var res bytes.Buffer
	for i := len(n) - 1; i >= 0; i-- {
		atavList := n[i]
		sort.Sort(byX501Canonical(atavList))

		for _, atav := range atavList {
			fmt.Fprintf(&res, "%s=", atav.Type.String())
			switch val := atav.Value.(type) {
			case string:
				length := len(val)
				if length == 0 {
					break
				}

				index := 0
				bufStart := res.Len()
				bufLen := 0
				if val[0] == '#' {
					res.WriteString("\\#")
					index++
				}

				for ; index < length; index++ {
					switch val[index] {
					case ' ':
						bufLen = res.Len() - bufStart
						if bufLen == 0 || res.Bytes()[res.Len()-1] == ' ' {
							break
						}
						res.WriteByte(' ')
					case '"', '\\', ',', '+', '<', '>', ';':
						res.WriteByte('\\')
					default:
						res.WriteByte(val[index])
					}
				}

				x := res.Len() - 1
				for x >= bufStart && res.Bytes()[x] == ' ' {
					x--
				}
				res.Truncate(x + 1)
			default:
				fmt.Fprintf(&res, "%v", atav.Value)
			}
			res.WriteByte('+')
		}

		// remove last +
		if len(atavList) != 0 {
			res.Truncate(res.Len() - 1)
		}

		if i != 0 {
			res.WriteByte(',')
		}
	}
	return strings.ToLower(res.String())
}
