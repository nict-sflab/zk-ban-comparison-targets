package abration

import (
	zkbancircuit "github.com/akakou/zk-ban/circuit"
	"github.com/akakou/zk-ban/snark"
	"github.com/consensys/gnark/frontend"
)

type UpdateCircuit struct {
	SecretKey      frontend.Variable `gnark:",secret"`
	RevocationList zkbancircuit.RevocationList
}

func (circuit *UpdateCircuit) Define(api frontend.API) error {
	for _, revokedPerPeriod := range circuit.RevocationList {
		for counter := range zkbancircuit.MaxSession {
			sessionTag := zkbancircuit.SessionTag(api, revokedPerPeriod.Period, counter)
			nym, err := snark.CircuitHash(api, sessionTag, circuit.SecretKey)
			if err != nil {
				return err
			}

			for _, revokedNym := range revokedPerPeriod.Nyms {
				api.AssertIsDifferent(nym, revokedNym)
			}
		}
	}

	return nil
}
