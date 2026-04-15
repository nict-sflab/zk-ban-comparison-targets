package abration

import (
	zkbancircuit "github.com/akakou/zk-ban/circuit"
	"github.com/consensys/gnark/frontend"
)

type UpdateCircuit struct {
	SecretKey      frontend.Variable `gnark:",secret"`
	RevocationList zkbancircuit.RevocationList
}

func (circuit *UpdateCircuit) Define(api frontend.API) error {
	err := circuit.RevocationList.CheckRevocation(circuit.SecretKey, api)
	if err != nil {
		return err
	}

	return nil
}
