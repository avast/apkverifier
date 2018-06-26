package signingblock

import (
	"bytes"
	"io"
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"encoding/hex"
)

type V3LineageSigningCertificateNode struct {
	SigningCert *x509.Certificate
	ParentSigAlgorithm SignatureAlgorithm
	SigAlgorithm SignatureAlgorithm
	Signature []byte
	Flags int32
}

func (n *V3LineageSigningCertificateNode) Equal(o *V3LineageSigningCertificateNode) bool {
	if n == o {
		return true
	}

	if !n.SigningCert.Equal(o.SigningCert) {
		return false
	}

	if n.ParentSigAlgorithm != o.ParentSigAlgorithm {
		return false
	}

	if n.SigAlgorithm != o.SigAlgorithm {
		return false
	}

	if !bytes.Equal(n.Signature, o.Signature) {
		return false
	}

	if n.Flags != o.Flags {
		return false
	}

	return true
}

func (n *V3LineageSigningCertificateNode) Dump(w io.Writer) error {
	sha1sum := sha1.Sum(n.SigningCert.Raw)
	if _, err := fmt.Fprintf(w, "Cert %s:\n", hex.EncodeToString(sha1sum[:])); err != nil {
		return err
	}

	_, err := fmt.Fprintf(w, "  ValidFrom: %v\n  ValidTo: %d\n", n.SigningCert.NotBefore, n.SigningCert.NotAfter)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(w, "  Issuer: %s\n  Subject: %s\n", PkixNameToString(&n.SigningCert.Issuer), PkixNameToString(&n.SigningCert.Subject));
	if err != nil {
		return err
	}

	if _, err := fmt.Fprintf(w, "ParentSigAlgorithm: %s\n", n.ParentSigAlgorithm.String()); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(w, "SigAlgorithm: %s\n", n.SigAlgorithm.String()); err != nil {
		return err
	}

	sha1sum = sha1.Sum(n.Signature)
	if _, err := fmt.Fprintf(w, "Signature: %s\n", hex.EncodeToString(sha1sum[:])); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(w, "Flags: 0x%04x\n", n.Flags); err != nil {
		return err
	}
	return nil
}

type V3LineageSigningCertificateNodeList []*V3LineageSigningCertificateNode

func (l V3LineageSigningCertificateNodeList) Equal(o V3LineageSigningCertificateNodeList) bool {
	if len(l) != len(o) {
		return false
	}

	for i := range l {
		if !l[i].Equal(o[i]) {
			return false
		}
	}
	return true
}

func lineageCalculateMinSdkVersion(nodes V3LineageSigningCertificateNodeList) int {
	minSdkVersion := 28 // lineage introduced in P
	for _, n := range nodes {
		if n.SigAlgorithm.isSupported() {
			if nmin := n.SigAlgorithm.getMinSdkVersion(); nmin > minSdkVersion {
				minSdkVersion = nmin
			}
		}
	}
	return minSdkVersion
}

type V3SigningLineage struct {
	MinSdkVersion int
	Nodes V3LineageSigningCertificateNodeList
}

func (l *V3SigningLineage) getSubLineage(cert *x509.Certificate) (*V3SigningLineage, error) {
	for i, n := range l.Nodes {
		if n.SigningCert.Equal(cert) {
			return &V3SigningLineage{
				MinSdkVersion: l.MinSdkVersion,
				Nodes: l.Nodes[0:i+1],
			}, nil
		}
	}
	return nil, fmt.Errorf("certificate not found in signing lineage")
}
