package circuit

import (
	"github.com/consensys/gnark-crypto/ecc"
	//"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
)

type MimcCircuit struct {
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

func (circuit *MimcCircuit) Define(api frontend.API) error {
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	mimc.Write(circuit.PreImage)

	api.Println("m: ", mimc.Sum())
	api.Println("p: ", circuit.PreImage)
	api.Println("h: ", circuit.Hash)

	api.AssertIsEqual(mimc.Sum(), circuit.Hash)

	return nil
}

func MakeConstraintSystem() (constraint.ConstraintSystem, error) {
	var mimcCircuit MimcCircuit

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &mimcCircuit)
	if err != nil {
		return nil, err
	}

	return ccs, nil
}
