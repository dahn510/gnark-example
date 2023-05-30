package prover

import (
	"fmt"
	"math/big"

	"github.com/dahn510/gnark-example/circuit"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
)

// Hash arbitrary message to create gnark-crypto mimc compatible pre-image
func MakePreImage(msg []byte) ([]byte, error) {
	count := len(msg)/mimc.BlockSize
	if len(msg) < mimc.BlockSize {
		count = 1
	}
	element, err := fr.Hash(msg, []byte("string:"), count)
	if err != nil {
		return nil, err
	}
	// convert [32]byte to []byte slice
	var bz []byte
	for _, e := range element {
		b := e.Bytes() // make addressable memory on heap
		bz = append(bz, b[:]...)
	}

	return bz, nil
}

func MakeWitness(preImage []byte) (witness.Witness, error) {
	h := hash.MIMC_BN254.New()
	_, err := h.Write(preImage)
	if err != nil {
		return nil, err
	}

	// *Public variable
	hash := big.NewInt(0).SetBytes(h.Sum(nil))
	assignment := circuit.MimcCircuit{PreImage: preImage, Hash: hash}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	return witness, nil
}
