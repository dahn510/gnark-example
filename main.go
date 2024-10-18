package main

import (
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
)

type Circuit struct {
	Secret frontend.Variable
	Hash   frontend.Variable `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	mimc.Write(circuit.Secret)

	api.Println("m: ", mimc.Sum())
	api.Println("p: ", circuit.Secret)
	api.Println("h: ", circuit.Hash)

	api.AssertIsEqual(mimc.Sum(), circuit.Hash)

	return nil
}

func Hash(data []byte, hashFunc hash.Hash) []byte {
	h := hashFunc.New()
	h.Write(data)
	return h.Sum(nil)
}

func main() {
	curve := ecc.BN254

	msg := []byte("small secret msg")
	preMsg := big.NewInt(0)
	preMsg.SetBytes(msg)

	preImg := preMsg.Bytes()

	//hash: expected hash using circuit counterpart
	hashFunc := hash.MIMC_BN254
	hash := Hash(preImg, hashFunc)

	var cir Circuit
	ccs, err := frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, &cir)
	if err != nil {
		log.Fatal(err)
	}

	asgn := Circuit{
		Secret: preMsg,
		Hash:   hash,
	}

	witness, err := frontend.NewWitness(&asgn, curve.ScalarField())
	if err != nil {
		log.Fatal(err)
	}

	witnessPublic, err := witness.Public()
	if err != nil {
		log.Fatal(err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatal(err)
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Fatal(err)
	}

	err = groth16.Verify(proof, vk, witnessPublic)
	if err != nil {
		log.Fatal(err)
	}
}
