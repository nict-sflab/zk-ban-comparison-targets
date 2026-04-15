package abration

import (
	"github.com/akakou/zk-ban/snark"
	"github.com/consensys/gnark/frontend"
)

type ClassicRevocationEntry struct {
	Tag frontend.Variable
	Nym frontend.Variable
}

type ClassicCircuit struct {
	Entries   []ClassicRevocationEntry `gnark:",public"`
	SecretKey frontend.Variable        `gnark:",secret"`
}

func (circuit *ClassicCircuit) Define(api frontend.API) error {
	for _, entry := range circuit.Entries {
		nym, err := snark.CircuitHash(api, entry.Tag, circuit.SecretKey)
		if err != nil {
			return err
		}

		api.AssertIsDifferent(nym, entry.Nym)
	}

	return nil
}
