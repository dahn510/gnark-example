package merkletree

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	//"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

func MakePreImage(msg []byte) ([]byte, error) {
	count := (len(msg) + mimc.BlockSize - 1) / int(mimc.BlockSize) // ceiling
	dst := make([]byte, 0, count*mimc.BlockSize)
	el, err := fr.Hash(msg, []byte(""), count)
	if err != nil {
		return nil, err
	}

	for i := range el {
		e := el[i].Bytes()
		dst = append(dst, e[:]...)
	}
	return dst, nil
}

func TestSimpleMerkleTree(t *testing.T) {
	proofIndex := 0
	leafCount := 6
	segmentSize := mimc.BlockSize
	assert := test.NewAssert(t)

	var buf bytes.Buffer
	data := make([]byte, segmentSize*leafCount)
	n, err := rand.Read(data)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(data) {
		t.Fatal("could not fill data buffer")
	}

	preImg, err := MakePreImage(data)
	if err != nil {
		t.Fatal(err)
	}

	_, err = buf.Write(preImg)
	if err != nil {
		t.Fatal(err)
	}

	h := hash.MIMC_BN254.New()

	root, proofSet, numLeaves, err := merkletree.BuildReaderProof(&buf, h, segmentSize, uint64(proofIndex))
	if err != nil {
		t.Fatal(err)
	}

	valid := merkletree.VerifyProof(h, root, proofSet, uint64(proofIndex), numLeaves)
	if !valid {
		t.Fatal("proof is not falid")
	}

	var mpCircuit MerkleTree
	mpCircuit.LeafIndex = proofIndex
	mpCircuit.Path = make([]frontend.Variable, len(proofSet))
	mpCircuit.Root = root
	for i := range mpCircuit.Path {
		mpCircuit.Path[i] = proofSet[i]
	}

	var circuit MerkleTree
	circuit.Path = make([]frontend.Variable, len(proofSet))
	assert.ProverSucceeded(&circuit, &mpCircuit, test.WithCurves(ecc.BN254))

	mpCircuit.LeafIndex = 3
	assert.ProverFailed(&circuit, &mpCircuit, test.WithCurves(ecc.BN254))
}
