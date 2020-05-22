package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
)

var hashString string
var supportedAlgs = []string{"md5", "sha1", "sha256"}

func main() {
	flag.StringVar(&hashString, "compare", "", "The hash to be compared with the file hash")
	flag.Parse()

	hashString = strings.TrimSpace(hashString)
	var alg string
	var path string

	if len(flag.Args()) > 1 {
		alg = strings.TrimSpace(flag.Arg(0))
		path = strings.TrimSpace(flag.Arg(1))
	} else {
		alg = "md5"
		path = strings.TrimSpace(flag.Arg(0))
	}

	if !isAlgorithmSupported(alg) {
		fmt.Println("algorithm type not supported")
		os.Exit(1)
	}

	var contentReader io.Reader
	var err error

	if path == "" {
		stdinfo, err := os.Stdin.Stat()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if (stdinfo.Mode() & os.ModeCharDevice) != 0 {
			fmt.Println("no file or path provided")
			os.Exit(1)
		}

		contentReader = os.Stdin
	} else {
		contentReader, err = os.Open(path)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	if hashString == "" {
		print(alg, contentReader)
	} else {
		compare(alg, contentReader)
	}
}

func print(alg string, r io.Reader) {
	fileHash, err := generateHash(alg, r)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(fileHash)
}

func compare(alg string, r io.Reader) {
	fileHash, err := generateHash(alg, r)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if fileHash == hashString {
		fmt.Println("Match!")
		os.Exit(0)
	}

	fmt.Println("Hashes doesn't match :(")
	os.Exit(2)
}

func generateHash(alg string, r io.Reader) (string, error) {
	var h hash.Hash

	switch alg {
	case "md5":
		h = md5.New()
	case "sha1":
		h = sha1.New()
	case "sha256":
		h = sha256.New()
	}

	return hashToString(h, r)
}

func hashToString(h hash.Hash, r io.Reader) (string, error) {
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func isAlgorithmSupported(alg string) bool {
	var supported bool
	for _, supportedAlg := range supportedAlgs {
		if alg != supportedAlg {
			continue
		}

		supported = true
		break
	}
	return supported
}
