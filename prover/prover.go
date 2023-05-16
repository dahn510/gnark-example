package prover

import (
	"github.com/dahn510/gnark-example/circuit"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
)

// Hash arbitrary message to create gnark-crypto mimc compatible pre-image
func MakePreImage(msg []byte) ([]byte, error) {
	element, err := fr.Hash(msg, []byte("string:"), 1)
	if err != nil {
		return nil, err
	}
	// convert [32]byte to []byte slice
	bz := element[0].Bytes() // make addressable memory on heap

	return bz[:], nil
}

func MakeWitness(preImage []byte) (witness.Witness, error) {
	h := hash.MIMC_BN254.New()
	_, err := h.Write(preImage)
	if err != nil {
		return nil, err
	}

	// *Public variable
	hash := h.Sum(nil)
	assignment := circuit.MimcCircuit{PreImage: preImage, Hash: hash}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	return witness, nil
}
