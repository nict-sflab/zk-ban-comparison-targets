package bench_test

import (
	"bytes"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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

var (
	classicBenchRevocationCounts = []int{
		2569, 796, 30000,
	}
	zkBanBenchCircuitSizes = []zkbanwitness.RevocationListSize{
		{3697, 113, 99, 68, 48, 6, 4, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		zkbantest.EmptyUniformRevocationList(30, 30000).Sizes(),
	}
)

var benchSecret = zkbanwitness.InitBigInt()

func BenchmarkClassic(b *testing.B) {
	for _, revocationCount := range classicBenchRevocationCounts {
		b.Run(fmt.Sprintf("revocations=%d", revocationCount), func(b *testing.B) {
			benchmarkClassic(b, revocationCount)
		})
	}
}

func benchmarkClassic(b *testing.B, revocationCount int) {
	fmt.Println("ready...")
	template, assignment := classicCircuitsForBench(b, revocationCount)
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
	for _, circuitSizes := range zkBanBenchCircuitSizes {
		b.Run(zkBanBenchmarkName(circuitSizes), func(b *testing.B) {
			benchmarkZKBan(b, circuitSizes)
		})
	}
}

func benchmarkZKBan(b *testing.B, circuitSizes zkbanwitness.RevocationListSize) {
	fmt.Println("ready...")
	template, assignment := zkbanCircuitsForBench(circuitSizes)
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

func classicCircuitsForBench(tb testing.TB, revocationCount int) (frontend.Circuit, frontend.Circuit) {
	tb.Helper()
	zkbanwitness.InitBigInt = zkbantest.InitBigInt

	template := &abr.ClassicCircuit{
		Entries: make([]abr.ClassicRevocationEntry, revocationCount),
	}

	tagBase := zkbanwitness.InitBigInt()
	tag := tagBase.Add(&tagBase.Int, big.NewInt(1))
	entries := []abr.ClassicRevocationEntry{}
	emptyNym := zkbantest.InitBigInt()

	for i := 0; i < revocationCount; i++ {
		entry := abr.ClassicRevocationEntry{
			Tag: *tag,
			Nym: emptyNym.Int,
		}

		entries = append(entries, entry)
	}

	assignment := &abr.ClassicCircuit{
		Entries:   entries,
		SecretKey: &benchSecret.Int,
	}
	return template, assignment
}

func zkBanBenchmarkName(circuitSizes zkbanwitness.RevocationListSize) string {
	parts := make([]string, len(circuitSizes))
	for i, size := range circuitSizes {
		parts[i] = strconv.Itoa(size)
	}
	return "circuit_sizes=" + strings.Join(parts, ",")
}

func zkbanCircuitsForBench(circuitSizes zkbanwitness.RevocationListSize) (frontend.Circuit, frontend.Circuit) {
	zkbanwitness.InitBigInt = zkbantest.InitBigInt
	revocationList := zkbanwitness.EmptyRevocationList(circuitSizes)
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

	ccsInfo, err := os.Stat(ccsPath)
	if err != nil {
		b.Fatal(err)
	}
	pkInfo, err := os.Stat(pkPath)
	if err != nil {
		b.Fatal(err)
	}

	fmt.Printf(
		"constraints=%d ccs_size=%s proving_key_size=%s\n",
		ccs.GetNbConstraints(),
		formatBytes(ccsInfo.Size()),
		formatBytes(pkInfo.Size()),
	)

	return dumpedBenchArtifacts{
		ccsPath: ccsPath,
		pkPath:  pkPath,
	}
}

func formatBytes(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for val := n / unit; val >= unit; val /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.3f %cB", float64(n)/float64(div), "KMGTPE"[exp])
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
