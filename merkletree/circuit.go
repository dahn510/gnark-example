package merkletree

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash/mimc"
)

type MerkleTree struct {
	Path      []frontend.Variable
	Root      frontend.Variable `gnark:",public"`
	LeafIndex frontend.Variable
}

func (m MerkleTree) Define(api frontend.API) error {
	mp := merkle.MerkleProof{
		Path:     m.Path,
		RootHash: m.Root,
	}
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	mp.VerifyProof(api, &h, m.LeafIndex)
	return nil
}
