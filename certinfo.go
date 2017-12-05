package apkverifier

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

type CertInfo struct {
	Md5                string
	Sha1               string
	Sha256             string
	ValidFrom, ValidTo time.Time
	Issuer, Subject    string
}

type byPreference [][]*x509.Certificate

func (c byPreference) Len() int      { return len(c) }
func (c byPreference) Swap(i, j int) { c[i], c[j] = c[j], c[i] }
func (c byPreference) Less(i, j int) bool {
	ci, cj := c[i][0], c[j][0]

	if ci.SignatureAlgorithm != cj.SignatureAlgorithm {
		return ci.SignatureAlgorithm > cj.SignatureAlgorithm
	}

	now := time.Now()
	// expired cert is "More" than not-expired one
	if ci.NotAfter.After(now) || ci.NotBefore.Before(now) {
		return false
	} else if cj.NotAfter.After(now) || cj.NotBefore.Before(now) {
		return true
	}

	if !ci.NotBefore.Equal(cj.NotBefore) {
		return ci.NotBefore.After(cj.NotBefore)
	}
	return ci.NotAfter.Sub(ci.NotBefore) > cj.NotAfter.Sub(cj.NotBefore)
}

func PickBestApkCert(chains [][]*x509.Certificate) (*CertInfo, *x509.Certificate) {
	if len(chains) == 0 {
		return nil, nil
	}

	sort.Sort(byPreference(chains))

	var res CertInfo
	res.Fill(chains[0][0])
	return &res, chains[0][0]
}

func (ci *CertInfo) Fill(cert *x509.Certificate) {
	md5sum := md5.Sum(cert.Raw)
	sha1sum := sha1.Sum(cert.Raw)
	sha256sum := sha256.Sum256(cert.Raw)

	ci.Md5 = hex.EncodeToString(md5sum[:])
	ci.Sha1 = hex.EncodeToString(sha1sum[:])
	ci.Sha256 = hex.EncodeToString(sha256sum[:])
	ci.ValidFrom = cert.NotBefore
	ci.ValidTo = cert.NotAfter
	ci.Issuer = ci.pkixNameToString(&cert.Issuer)
	ci.Subject = ci.pkixNameToString(&cert.Subject)
}

func (ci *CertInfo) pkixNameToString(n *pkix.Name) string {
	var buf bytes.Buffer

	if len(n.Country) != 0 {
		fmt.Fprintf(&buf, "C=%s, ", strings.Join(n.Country, ";"))
	}
	if len(n.Province) != 0 {
		fmt.Fprintf(&buf, "ST=%s, ", strings.Join(n.Province, ";"))
	}
	if len(n.Locality) != 0 {
		fmt.Fprintf(&buf, "L=%s, ", strings.Join(n.Locality, ";"))
	}
	if len(n.Organization) != 0 {
		fmt.Fprintf(&buf, "O=%s, ", strings.Join(n.Organization, ";"))
	}
	if len(n.OrganizationalUnit) != 0 {
		fmt.Fprintf(&buf, "OU=%s, ", strings.Join(n.OrganizationalUnit, ";"))
	}
	if len(n.CommonName) != 0 {
		fmt.Fprintf(&buf, "CN=%s, ", n.CommonName)
	}

	// Remove last ', '
	if buf.Len() != 0 {
		buf.Truncate(buf.Len() - 2)
	}

	return buf.String()
}
