package merkletree

import (
	"bytes"
	"crypto/rand"
	"math"
	"testing"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"

	//"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
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

func BenchmarkCompileAndBuild(b *testing.B) {
	b.StopTimer()

	proofIndex := 0
	leafCount := 8
	segmentSize := mimc.BlockSize

	data := make([]byte, segmentSize*leafCount)
	proofSize := math.Log2(float64(leafCount))
	proofSize = math.Ceil(proofSize)
	if math.IsInf(proofSize, 0) {
		b.Fatal("could not determine proof size")
	}
	proofSize += 1
	b.Logf("proof size: %v", proofSize)

	var circuit MerkleTree
	circuit.Path = make([]frontend.Variable, int(proofSize))
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		b.Fatal(err)
	}

	pk, _, err := groth16.Setup(cs)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		n, err := rand.Read(data)
		if err != nil {
			b.Fatal(err)
		}
		if n != len(data) {
			b.Fatal("could not fill data buffer")
		}

		preImg, err := MakePreImage(data)
		if err != nil {
			b.Fatal(err)
		}

		var buf bytes.Buffer
		_, _ = buf.Write(preImg)

		b.StartTimer()

		h := hash.MIMC_BN254.New()

		root, proofSet, numLeaves, err := merkletree.BuildReaderProof(&buf, h, segmentSize, uint64(proofIndex))
		if err != nil {
			b.Fatal(err)
		}
		b.Logf("proof set size: %v", len(proofSet))

		valid := merkletree.VerifyProof(h, root, proofSet, uint64(proofIndex), numLeaves)
		if !valid {
			b.Fatal("proof is not falid")
		}

		var mpCircuit MerkleTree
		mpCircuit.LeafIndex = proofIndex
		mpCircuit.Path = make([]frontend.Variable, len(proofSet))
		mpCircuit.Root = root
		for i := range mpCircuit.Path {
			mpCircuit.Path[i] = proofSet[i]
		}

		witness, err := frontend.NewWitness(&mpCircuit, ecc.BN254.ScalarField())
		if err != nil {
			b.Fatal(err)
		}

		proof, err := groth16.Prove(cs, pk, witness)
		if err != nil {
			b.Fatal(err)
		}
		_ = proof

		pbuf := bytes.NewBuffer(nil)

		size, err := proof.WriteTo(pbuf)
		if err != nil {
			b.Fatal(err)
		}

		b.Logf("serialized proof size: %v", size)
	}
}
