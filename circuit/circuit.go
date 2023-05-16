package circuit

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
)

type CircuitData struct {
	Circuit frontend.Circuit
	CS constraint.ConstraintSystem
	Curve ecc.ID
	PK groth16.ProvingKey
	VK groth16.VerifyingKey
}

type ICircuit interface {
	CreateProof(witness witness.Witness, circuitData CircuitData) (groth16.Proof, error)
	VerifyProof(proof groth16.Proof, publicWitness witness.Witness, circuitData CircuitData) error
}
