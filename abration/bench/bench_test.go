package bench_test

import (
	"bytes"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	abr "github.com/akakou/zk-ban-comparisons/abration"
	zkbancircuit "github.com/akakou/zk-ban/circuit"
	zkbansnark "github.com/akakou/zk-ban/snark"
	zkbantest "github.com/akakou/zk-ban/test"
	zkbanwitness "github.com/akakou/zk-ban/witness"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const (
	benchRevocations = 30000
	benchT           = 30
)

var benchSecret = zkbanwitness.InitBigInt()

func BenchmarkClassic(b *testing.B) {
	fmt.Println("ready...")
	template, assignment := classicCircuitsForBench(b)
	dumps := dumpBenchArtifacts(b, template)

	fmt.Println("start...")
	runtime.GC()

	b.ResetTimer()
	for range b.N {
		ccs, pk := loadBenchArtifacts(b, dumps)
		wit, err := frontend.NewWitness(assignment, zkbansnark.EcCurve.ScalarField())
		if err != nil {
			b.Fatal(err)
		}
		if _, err := groth16.Prove(ccs, pk, wit); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkZKBan(b *testing.B) {
	fmt.Println("ready...")
	template, assignment := zkbanCircuitsForBench()
	dumps := dumpBenchArtifacts(b, template)

	fmt.Println("start...")
	runtime.GC()

	b.ResetTimer()
	for range b.N {
		ccs, pk := loadBenchArtifacts(b, dumps)
		wit, err := frontend.NewWitness(assignment, zkbansnark.EcCurve.ScalarField())
		if err != nil {
			b.Fatal(err)
		}
		if _, err := groth16.Prove(ccs, pk, wit); err != nil {
			b.Fatal(err)
		}
	}
}

func classicCircuitsForBench(b *testing.B) (frontend.Circuit, frontend.Circuit) {
	b.Helper()

	template := &abr.ClassicCircuit{
		Entries: make([]abr.ClassicRevocationEntry, benchRevocations),
	}

	tagBase := zkbanwitness.InitBigInt()
	tag := tagBase.Add(&tagBase.Int, big.NewInt(1))
	entries := []abr.ClassicRevocationEntry{}

	nym, err := zkbansnark.CommitHash(tag, &benchSecret.Int)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < benchRevocations; i++ {
		entry := abr.ClassicRevocationEntry{
			Tag: *tag,
			Nym: *nym,
		}

		entries = append(entries, entry)
	}

	assignment := &abr.ClassicCircuit{
		Entries:   entries,
		SecretKey: &benchSecret.Int,
	}
	return template, assignment
}

func zkbanCircuitsForBench() (frontend.Circuit, frontend.Circuit) {
	revocationList := zkbantest.EmptyUniformRevocationList(benchT, benchRevocations)
	templateAssigned := zkbancircuit.NewRevocationListAssigned(revocationList)
	witnessAssigned := zkbancircuit.NewRevocationListAssigned(revocationList)

	template := &abr.UpdateCircuit{
		RevocationList: templateAssigned,
	}

	assignment := &abr.UpdateCircuit{
		SecretKey:      &benchSecret.Int,
		RevocationList: witnessAssigned,
	}
	return template, assignment
}

type dumpedBenchArtifacts struct {
	ccsPath string
	pkPath  string
}

func dumpBenchArtifacts(b *testing.B, template frontend.Circuit) dumpedBenchArtifacts {
	b.Helper()

	ccs, pk := compileBenchCircuit(b, template)
	dir := b.TempDir()

	ccsPath := filepath.Join(dir, "ccs.bin")
	ccsFile, err := os.Create(ccsPath)
	if err != nil {
		b.Fatal(err)
	}
	defer ccsFile.Close()

	if _, err := ccs.WriteTo(ccsFile); err != nil {
		b.Fatal(err)
	}

	pkPath := filepath.Join(dir, "pk.dump")
	pkFile, err := os.Create(pkPath)
	if err != nil {
		b.Fatal(err)
	}
	defer pkFile.Close()

	if err := pk.WriteDump(pkFile); err != nil {
		b.Fatal(err)
	}

	return dumpedBenchArtifacts{
		ccsPath: ccsPath,
		pkPath:  pkPath,
	}
}

func loadBenchArtifacts(
	b *testing.B,
	dumps dumpedBenchArtifacts,
) (constraint.ConstraintSystem, groth16.ProvingKey) {
	b.Helper()

	pkBin, err := os.ReadFile(dumps.pkPath)
	if err != nil {
		b.Fatal(err)
	}

	pk := groth16.NewProvingKey(zkbansnark.EcCurve)
	if err := pk.ReadDump(bytes.NewReader(pkBin)); err != nil {
		b.Fatal(err)
	}

	ccsBin, err := os.ReadFile(dumps.ccsPath)
	if err != nil {
		b.Fatal(err)
	}

	ccs := groth16.NewCS(zkbansnark.EcCurve)
	if _, err := ccs.ReadFrom(bytes.NewReader(ccsBin)); err != nil {
		b.Fatal(err)
	}

	return ccs, pk
}

func compileBenchCircuit(
	b *testing.B,
	template frontend.Circuit,
) (constraint.ConstraintSystem, groth16.ProvingKey) {
	b.Helper()

	ccs, err := frontend.Compile(zkbansnark.EcCurve.ScalarField(), r1cs.NewBuilder, template)
	if err != nil {
		b.Fatal(err)
	}
	pk, _, err := groth16.Setup(ccs)
	if err != nil {
		b.Fatal(err)
	}
	return ccs, pk
}
