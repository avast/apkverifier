package apkverifier_test

import (
	"fmt"
	"github.com/avast/apkverifier"
	"os"
)

func Example() {
	res, err := apkverifier.Verify(os.Args[1], nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Verification failed: %s\n", err.Error())
	}

	fmt.Printf("Uses scheme v2: %v\n", res.UsingSchemeV2)
	cert, _ := apkverifier.PickBestApkCert(res.SignerCerts)
	if cert == nil {
		fmt.Printf("No certificate found.\n")
	} else {
		fmt.Println(cert)
	}
}
