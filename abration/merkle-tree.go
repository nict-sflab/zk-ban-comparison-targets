package abration

import (
	zkbancircuit "github.com/akakou/zk-ban/circuit"
	"github.com/akakou/zk-ban/snark"
	"github.com/consensys/gnark/frontend"
)

const (
	merkleLeafDomain = int64(1001)
	merkleNodeDomain = int64(1002)
)

type MerkleMembershipProof struct {
	Leaf     frontend.Variable
	Index    frontend.Variable
	Siblings []frontend.Variable
}

type NymNonMembershipProof struct {
	Left  MerkleMembershipProof
	Right MerkleMembershipProof
}

type SessionRevocationAccumulator struct {
	Root          frontend.Variable `gnark:",public"`
	Period        frontend.Variable `gnark:",public"`
	CounterProofs []NymNonMembershipProof
}

type RevocationAccumulator []SessionRevocationAccumulator

type MerkleTreeCircuit struct {
	SecretKey             frontend.Variable     `gnark:",secret"`
	RevocationAccumulator RevocationAccumulator `gnark:",public"`
}

func (circuit *MerkleTreeCircuit) Define(api frontend.API) error {
	for _, revokedPerSession := range circuit.RevocationAccumulator {
		for counter, proof := range revokedPerSession.CounterProofs {
			sessionTag := zkbancircuit.SessionTag(api, revokedPerSession.Period, counter)
			nym, err := snark.CircuitHash(api, sessionTag, circuit.SecretKey)
			if err != nil {
				return err
			}

			err = verifyNymNonMembership(api, revokedPerSession.Root, nym, proof)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func verifyMerkleMembership(
	api frontend.API,
	root frontend.Variable,
	proof MerkleMembershipProof,
) error {
	digest, err := snark.CircuitHash(api, merkleLeafDomain, proof.Leaf)
	if err != nil {
		return err
	}

	indexBits := api.ToBinary(proof.Index, len(proof.Siblings))
	for depth, sibling := range proof.Siblings {
		left := api.Select(indexBits[depth], sibling, digest)
		right := api.Select(indexBits[depth], digest, sibling)

		digest, err = snark.CircuitHash(api, merkleNodeDomain, left, right)
		if err != nil {
			return err
		}
	}

	api.AssertIsEqual(digest, root)
	return nil
}

func verifyNymNonMembership(
	api frontend.API,
	root frontend.Variable,
	nym frontend.Variable,
	proof NymNonMembershipProof,
) error {
	if err := verifyMerkleMembership(api, root, proof.Left); err != nil {
		return err
	}
	if err := verifyMerkleMembership(api, root, proof.Right); err != nil {
		return err
	}

	api.AssertIsEqual(proof.Right.Index, api.Add(proof.Left.Index, 1))

	api.AssertIsLessOrEqual(proof.Left.Leaf, nym)
	api.AssertIsLessOrEqual(nym, proof.Right.Leaf)
	api.AssertIsDifferent(nym, proof.Left.Leaf)
	api.AssertIsDifferent(nym, proof.Right.Leaf)

	return nil
}
