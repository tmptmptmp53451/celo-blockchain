// package tests

package tests

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/tests"
)

// func TestCall(t *testing.T) {
// 	ret, gas, err := evm.Call(AccountRef(common.HexToAddress("0x0123456")), params.ReserveAddress, encodedAbi, gas, big.NewInt(0))
// }

func TestTobinTransfer(t *testing.T) {

	// type (
	// 	CanTransferFunc func(StateDB, common.Address, *big.Int) bool
	// )

	t.Logf("Initializing variables")
	var (
		testdb      = ethdb.NewMemDatabase()
		testKey, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		testAddress = crypto.PubkeyToAddress(testKey.PublicKey)
		// genesisBlock = core.GenesisBlockForTobinTaxTesting(testdb, testAddress, big.NewInt(1000000000))
		// genesisAlloc = genesisBlock.Alloc
		genesisBlock = core.TobinTaxGenesisBlock(15, testAddress)
		genesisAlloc = genesisBlock.Alloc
		statedb      = tests.MakePreState(testdb, genesisAlloc)
		context      = vm.Context{CanTransfer: core.CanTransfer, Transfer: core.Transfer}
		config       = vm.Config{}
		env          = vm.NewEVM(context, statedb, params.TestChainConfig, config)
	)
	t.Logf("Done initializing variables")

	t.Logf("tobin tax code: %v", statedb.GetCode(common.HexToAddress("0x000000000000000000000000000000000000abcd")))
	t.Logf("tobin tax address balance: %v", statedb.GetBalance(common.HexToAddress("0x000000000000000000000000000000000000abcd")))

	t.Logf("Starting TestTobinTransfer")
	amount := big.NewInt(1000000000000)
	// amount := big.NewInt(0)
	addr := common.HexToAddress("0x0123456")
	statedb.AddBalance(addr, amount)
	balance := statedb.GetBalance(addr)
	t.Logf("Getting balance: %v", balance)
	addr1 := common.HexToAddress("0x0123456abc")
	balance1 := statedb.GetBalance(addr1)
	t.Logf("Getting balance1: %v", balance1)
	reserveBalance := statedb.GetBalance(params.ReserveAddress)
	t.Logf("Getting reserveBalance: %v", reserveBalance)

	gas := uint64(3000000)

	tobinTax := new(big.Int).Div(new(big.Int).Mul(big.NewInt(25), amount), big.NewInt(100))
	t.Logf("Calculating tobinTax: %v", tobinTax)

	// log.Debug("Starting TobinTransfer")
	t.Logf("Starting TobinTransfer")
	gas, err := env.TobinTransfer(statedb, addr, addr1, gas, amount)
	t.Logf("TobinTransfer Complete")

	t.Logf("leftover gas: %v", gas)
	// log.Debug("TobinTransfer Complete")

	newBalance := statedb.GetBalance(addr)
	newBalance1 := statedb.GetBalance(addr1)
	newReserveBalance := statedb.GetBalance(params.ReserveAddress)

	if err != nil {
		t.Logf("EVM error: %v", err)
	}
	if statedb.GetBalance(addr).Cmp(new(big.Int).Sub(balance, amount)) != 0 {
		t.Logf("Did not complete transfer 1, actual: %v, expected: %v", newBalance, new(big.Int).Sub(balance, amount))
	}
	if statedb.GetBalance(addr1).Cmp(new(big.Int).Add(balance1, new(big.Int).Sub(amount, tobinTax))) != 0 {
		t.Logf("Did not complete transfer 2, actual: %v, expected: %v", newBalance1, new(big.Int).Add(balance1, new(big.Int).Sub(amount, tobinTax)))
	}
	if statedb.GetBalance(params.ReserveAddress).Cmp(new(big.Int).Add(reserveBalance, tobinTax)) != 0 {
		t.Logf("Did not complete transfer 3, actual: %v, expected: %v", newReserveBalance, new(big.Int).Add(reserveBalance, tobinTax))
	}
}
