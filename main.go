package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
)

type Circuit struct {
	Secret frontend.Variable
	Hash frontend.Variable `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	mimc.Write(circuit.Secret)
	api.AssertIsEqual(mimc.Sum(), circuit.Hash)

	return nil
}

func main() {
	// *Witness
	msg := "secret_something"

	// creating preImage
	h256 := sha256.New()
	h256.Write([]byte(msg))
	secret := h256.Sum(nil)

	element, err := fr.Hash([]byte(secret), []byte("string:"), 1)
	if err != nil {
		panic(err)
	}
	bz := element[0].Bytes() // make addressable memory on heap

	h := hash.MIMC_BN254.New()
	_, err = h.Write(bz[:])
	if err != nil {
		panic(err)
	}
	hash := h.Sum(nil)
	// debug
	fmt.Printf("Hash(public): %s\n", big.NewInt(0).SetBytes(hash).String())
	fmt.Printf("PreImage(secret): %s\n", big.NewInt(0).SetBytes(bz[:]).String())

	// *Prover
	// create proof
	assignment := Circuit{Secret: bz[:], Hash: hash}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	witnessPublic, err := witness.Public()
	if err != nil {
		panic(err)
	}

	// *Verifier
	var mimcCircuit Circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &mimcCircuit)
	if err != nil {
		panic(err)
	}
	
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	// *Prover
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}

	// *Verifier
	err = groth16.Verify(proof, vk, witnessPublic)
	if err != nil {
		panic(err)
	}
}
