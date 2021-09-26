package main

import (
	"bytes"
	"errors"
	"math/big"

	log "github.com/sirupsen/logrus"
)

type RansomEXXDecryptConfig struct {
	RSAPublicMod           *big.Int
	RSAPublicExponent      *big.Int
	RSAPrivateExponent     *big.Int
	RSAFirstPrimeFactor    *big.Int
	RSASecondPrimeFactor   *big.Int
	RSADP                  *big.Int
	RSADQ                  *big.Int
	RSAQP                  *big.Int
	EncryptedFileExtension string
	RansomNoteFilename     string
	DecryptLogicList       []DecryptLogic
}

type DecryptLogic struct {
	LowerLimit uint64
	UpperLimit uint64
	ChunkSize  uint64
	BlockSize  uint64
}

type Signature struct {
	Compare []byte
	Mask    []byte
}

func ApplyBitmask(data []byte, mask []byte) []byte {
	var ret []byte
	for i, b := range data {
		ret = append(ret, b&mask[i])
	}
	return ret
}

func FindWithSignature(data []byte, signature Signature) (uint64, error) {
	if len(signature.Compare) != len(signature.Mask) {
		log.Fatalln("Signature and mask are different lengths.")
	}

	// Apply the bitmask to the signature
	sig := ApplyBitmask(signature.Compare, signature.Mask)

	for i := range data {
		compare := ApplyBitmask(data[i:i+len(sig)], signature.Mask)
		if bytes.Compare(sig, compare) == 0 {
			log.Printf("Found a signature match at 0x%x\n", i)
			return uint64(i), nil
		}
	}

	return 0, errors.New("Failed to find a match for the given signature")
}
