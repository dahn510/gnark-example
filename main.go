package main

import (
	"github.com/dahn510/gnark-example/circuit"
	"github.com/dahn510/gnark-example/prover"


	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/backend/groth16"
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
	msg := "secret_something"

	ccs, err := circuit.MakeConstraintSystem()
	if err != nil {
		panic(err)
	}

	preImage, err := prover.MakePreImage([]byte(msg))
	if err != nil {
		panic(err)
	}

	witness, err := prover.MakeWitness(preImage)
	if err != nil {
		panic(err)
	}

	witnessPublic, err := witness.Public()
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}

	err = groth16.Verify(proof, vk, witnessPublic)
	if err != nil {
		panic(err)
	}
}
