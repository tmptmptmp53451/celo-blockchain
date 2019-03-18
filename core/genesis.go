// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

//go:generate gencodec -type Genesis -field-override genesisSpecMarshaling -out gen_genesis.go
//go:generate gencodec -type GenesisAccount -field-override genesisAccountMarshaling -out gen_genesis_account.go

var errGenesisNoConfig = errors.New("genesis has no chain configuration")

// Genesis specifies the header fields, state of a genesis block. It also defines hard
// fork switch-over blocks through the chain configuration.
type Genesis struct {
	Config     *params.ChainConfig `json:"config"`
	Nonce      uint64              `json:"nonce"`
	Timestamp  uint64              `json:"timestamp"`
	ExtraData  []byte              `json:"extraData"`
	GasLimit   uint64              `json:"gasLimit"   gencodec:"required"`
	Difficulty *big.Int            `json:"difficulty" gencodec:"required"`
	Mixhash    common.Hash         `json:"mixHash"`
	Coinbase   common.Address      `json:"coinbase"`
	Alloc      GenesisAlloc        `json:"alloc"      gencodec:"required"`

	// These fields are used for consensus tests. Please don't use them
	// in actual genesis blocks.
	Number     uint64      `json:"number"`
	GasUsed    uint64      `json:"gasUsed"`
	ParentHash common.Hash `json:"parentHash"`
}

// GenesisAlloc specifies the initial state that is part of the genesis block.
type GenesisAlloc map[common.Address]GenesisAccount

func (ga *GenesisAlloc) UnmarshalJSON(data []byte) error {
	m := make(map[common.UnprefixedAddress]GenesisAccount)
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*ga = make(GenesisAlloc)
	for addr, a := range m {
		(*ga)[common.Address(addr)] = a
	}
	return nil
}

// GenesisAccount is an account in the state of the genesis block.
type GenesisAccount struct {
	Code       []byte                      `json:"code,omitempty"`
	Storage    map[common.Hash]common.Hash `json:"storage,omitempty"`
	Balance    *big.Int                    `json:"balance" gencodec:"required"`
	Nonce      uint64                      `json:"nonce,omitempty"`
	PrivateKey []byte                      `json:"secretKey,omitempty"` // for tests
}

// field type overrides for gencodec
type genesisSpecMarshaling struct {
	Nonce      math.HexOrDecimal64
	Timestamp  math.HexOrDecimal64
	ExtraData  hexutil.Bytes
	GasLimit   math.HexOrDecimal64
	GasUsed    math.HexOrDecimal64
	Number     math.HexOrDecimal64
	Difficulty *math.HexOrDecimal256
	Alloc      map[common.UnprefixedAddress]GenesisAccount
}

type genesisAccountMarshaling struct {
	Code       hexutil.Bytes
	Balance    *math.HexOrDecimal256
	Nonce      math.HexOrDecimal64
	Storage    map[storageJSON]storageJSON
	PrivateKey hexutil.Bytes
}

// storageJSON represents a 256 bit byte array, but allows less than 256 bits when
// unmarshaling from hex.
type storageJSON common.Hash

func (h *storageJSON) UnmarshalText(text []byte) error {
	text = bytes.TrimPrefix(text, []byte("0x"))
	if len(text) > 64 {
		return fmt.Errorf("too many hex characters in storage key/value %q", text)
	}
	offset := len(h) - len(text)/2 // pad on the left
	if _, err := hex.Decode(h[offset:], text); err != nil {
		fmt.Println(err)
		return fmt.Errorf("invalid hex storage key/value %q", text)
	}
	return nil
}

func (h storageJSON) MarshalText() ([]byte, error) {
	return hexutil.Bytes(h[:]).MarshalText()
}

// GenesisMismatchError is raised when trying to overwrite an existing
// genesis block with an incompatible one.
type GenesisMismatchError struct {
	Stored, New common.Hash
}

func (e *GenesisMismatchError) Error() string {
	return fmt.Sprintf("database already contains an incompatible genesis block (have %x, new %x)", e.Stored[:8], e.New[:8])
}

// SetupGenesisBlock writes or updates the genesis block in db.
// The block that will be used is:
//
//                          genesis == nil       genesis != nil
//                       +------------------------------------------
//     db has no genesis |  main-net default  |  genesis
//     db has genesis    |  from DB           |  genesis (if compatible)
//
// The stored chain configuration will be updated if it is compatible (i.e. does not
// specify a fork block below the local head block). In case of a conflict, the
// error is a *params.ConfigCompatError and the new, unwritten config is returned.
//
// The returned chain configuration is never nil.
func SetupGenesisBlock(db ethdb.Database, genesis *Genesis) (*params.ChainConfig, common.Hash, error) {
	if genesis != nil && genesis.Config == nil {
		return params.AllEthashProtocolChanges, common.Hash{}, errGenesisNoConfig
	}

	// Just commit the new block if there is no stored genesis block.
	stored := rawdb.ReadCanonicalHash(db, 0)
	if (stored == common.Hash{}) {
		if genesis == nil {
			log.Info("Writing default main-net genesis block")
			genesis = DefaultGenesisBlock()
		} else {
			log.Info("Writing custom genesis block")
		}
		block, err := genesis.Commit(db)
		return genesis.Config, block.Hash(), err
	}

	// Check whether the genesis block is already written.
	if genesis != nil {
		hash := genesis.ToBlock(nil).Hash()
		if hash != stored {
			return genesis.Config, hash, &GenesisMismatchError{stored, hash}
		}
	}

	// Get the existing chain configuration.
	newcfg := genesis.configOrDefault(stored)
	storedcfg := rawdb.ReadChainConfig(db, stored)
	if storedcfg == nil {
		log.Warn("Found genesis block without chain config")
		rawdb.WriteChainConfig(db, stored, newcfg)
		return newcfg, stored, nil
	}
	// Special case: don't change the existing config of a non-mainnet chain if no new
	// config is supplied. These chains would get AllProtocolChanges (and a compat error)
	// if we just continued here.
	if genesis == nil && stored != params.MainnetGenesisHash {
		return storedcfg, stored, nil
	}

	// Check config compatibility and write the config. Compatibility errors
	// are returned to the caller unless we're already at block zero.
	height := rawdb.ReadHeaderNumber(db, rawdb.ReadHeadHeaderHash(db))
	if height == nil {
		return newcfg, stored, fmt.Errorf("missing block number for head header hash")
	}
	compatErr := storedcfg.CheckCompatible(newcfg, *height)
	if compatErr != nil && *height != 0 && compatErr.RewindTo != 0 {
		return newcfg, stored, compatErr
	}
	rawdb.WriteChainConfig(db, stored, newcfg)
	return newcfg, stored, nil
}

func (g *Genesis) configOrDefault(ghash common.Hash) *params.ChainConfig {
	switch {
	case g != nil:
		return g.Config
	case ghash == params.MainnetGenesisHash:
		return params.MainnetChainConfig
	case ghash == params.TestnetGenesisHash:
		return params.TestnetChainConfig
	default:
		return params.AllEthashProtocolChanges
	}
}

// ToBlock creates the genesis block and writes state of a genesis specification
// to the given database (or discards it if nil).
func (g *Genesis) ToBlock(db ethdb.Database) *types.Block {
	if db == nil {
		db = ethdb.NewMemDatabase()
	}
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(db))
	for addr, account := range g.Alloc {
		statedb.AddBalance(addr, account.Balance)
		statedb.SetCode(addr, account.Code)
		statedb.SetNonce(addr, account.Nonce)
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value)
		}
	}
	root := statedb.IntermediateRoot(false)
	head := &types.Header{
		Number:     new(big.Int).SetUint64(g.Number),
		Nonce:      types.EncodeNonce(g.Nonce),
		Time:       new(big.Int).SetUint64(g.Timestamp),
		ParentHash: g.ParentHash,
		Extra:      g.ExtraData,
		GasLimit:   g.GasLimit,
		GasUsed:    g.GasUsed,
		Difficulty: g.Difficulty,
		MixDigest:  g.Mixhash,
		Coinbase:   g.Coinbase,
		Root:       root,
	}
	if g.GasLimit == 0 {
		head.GasLimit = params.GenesisGasLimit
	}
	if g.Difficulty == nil {
		head.Difficulty = params.GenesisDifficulty
	}
	statedb.Commit(false)
	statedb.Database().TrieDB().Commit(root, true)

	return types.NewBlock(head, nil, nil, nil)
}

// Commit writes the block and state of a genesis specification to the database.
// The block is committed as the canonical head block.
func (g *Genesis) Commit(db ethdb.Database) (*types.Block, error) {
	block := g.ToBlock(db)
	if block.Number().Sign() != 0 {
		return nil, fmt.Errorf("can't commit genesis block with number > 0")
	}
	rawdb.WriteTd(db, block.Hash(), block.NumberU64(), g.Difficulty)
	rawdb.WriteBlock(db, block)
	rawdb.WriteReceipts(db, block.Hash(), block.NumberU64(), nil)
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteHeadBlockHash(db, block.Hash())
	rawdb.WriteHeadHeaderHash(db, block.Hash())

	config := g.Config
	if config == nil {
		config = params.AllEthashProtocolChanges
	}
	rawdb.WriteChainConfig(db, block.Hash(), config)
	return block, nil
}

// MustCommit writes the genesis block and state to db, panicking on error.
// The block is committed as the canonical head block.
func (g *Genesis) MustCommit(db ethdb.Database) *types.Block {
	block, err := g.Commit(db)
	if err != nil {
		panic(err)
	}
	return block
}

// GenesisBlockForTesting creates and writes a block in which addr has the given wei balance.
func GenesisBlockForTesting(db ethdb.Database, addr common.Address, balance *big.Int) *types.Block {
	g := Genesis{Alloc: GenesisAlloc{addr: {Balance: balance}}}
	return g.MustCommit(db)
}

// GenesisBlockForTobinTaxTesting creates and writes a block in which addr has the given wei balance.
// func GenesisBlockForTobinTaxTesting(db ethdb.Database, addr common.Address, balance *big.Int) Genesis {
// 	g := Genesis{Alloc: GenesisAlloc{addr: {Balance: balance}, "000000000000000000000000000000000000abcd": {code: "0x608060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806318ff9d23146044575b600080fd5b348015604f57600080fd5b5060566073565b604051808381526020018281526020019250505060405180910390f35b6000806000806019915060649050818193509350505090915600a165627a7a72305820c6501c6222f133f6155ad8a06b1f390eb2ef6e2703245dff2213bb28f3d072ba0029", "storage": {"0x34dc5a2556b2030988481969696f29fed38d45813d8003f6c70e5c16ac92ae0f": "99d0747412109de2cf530e71a427e6f22ab881b2"}, balance: 0}}}
// 	g.MustCommit(db)
// 	return g
// }

// DefaultGenesisBlock returns the Ethereum main net genesis block.
func DefaultGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.MainnetChainConfig,
		Nonce:      66,
		ExtraData:  hexutil.MustDecode("0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa"),
		GasLimit:   5000,
		Difficulty: big.NewInt(17179869184),
		Alloc:      decodePrealloc(mainnetAllocData),
	}
}

// DefaultTestnetGenesisBlock returns the Ropsten network genesis block.
func DefaultTestnetGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.TestnetChainConfig,
		Nonce:      66,
		ExtraData:  hexutil.MustDecode("0x3535353535353535353535353535353535353535353535353535353535353535"),
		GasLimit:   16777216,
		Difficulty: big.NewInt(1048576),
		Alloc:      decodePrealloc(testnetAllocData),
	}
}

// DefaultRinkebyGenesisBlock returns the Rinkeby network genesis block.
func DefaultRinkebyGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.RinkebyChainConfig,
		Timestamp:  1492009146,
		ExtraData:  hexutil.MustDecode("0x52657370656374206d7920617574686f7269746168207e452e436172746d616e000000000000000000000000000000000000000042eb768f2244c8811c63729a21a3569731535f067ffc57839b00206d1ad20c69a1981b489f772031b279182d99e65703f0076e4812653aab85fca0f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
		Alloc:      decodePrealloc(rinkebyAllocData),
	}
}

// DeveloperGenesisBlock returns the 'geth --dev' genesis block. Note, this must
// be seeded with the
func DeveloperGenesisBlock(period uint64, faucet common.Address) *Genesis {
	// Override the default period to the user requested one
	config := *params.AllCliqueProtocolChanges
	config.Clique.Period = period

	// Assemble and return the genesis with the precompiles and faucet pre-funded
	return &Genesis{
		Config:     &config,
		ExtraData:  append(append(make([]byte, 52), faucet[:]...), make([]byte, 65)...),
		GasLimit:   6283185,
		Difficulty: big.NewInt(1),
		Alloc: map[common.Address]GenesisAccount{
			common.BytesToAddress([]byte{1}): {Balance: big.NewInt(1)}, // ECRecover
			common.BytesToAddress([]byte{2}): {Balance: big.NewInt(1)}, // SHA256
			common.BytesToAddress([]byte{3}): {Balance: big.NewInt(1)}, // RIPEMD
			common.BytesToAddress([]byte{4}): {Balance: big.NewInt(1)}, // Identity
			common.BytesToAddress([]byte{5}): {Balance: big.NewInt(1)}, // ModExp
			common.BytesToAddress([]byte{6}): {Balance: big.NewInt(1)}, // ECAdd
			common.BytesToAddress([]byte{7}): {Balance: big.NewInt(1)}, // ECScalarMul
			common.BytesToAddress([]byte{8}): {Balance: big.NewInt(1)}, // ECPairing
			faucet:                           {Balance: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(9))},
		},
	}
}

// TobinTaxGenesisBlock returns the 'geth --dev' genesis block. Note, this must
// be seeded with the
func TobinTaxGenesisBlock(period uint64, faucet common.Address) *Genesis {
	// Override the default period to the user requested one
	config := *params.AllCliqueProtocolChanges
	config.Clique.Period = period

	// tobinTaxCode := "0x608060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806318ff9d23146044575b600080fd5b348015604f57600080fd5b5060566073565b604051808381526020018281526020019250505060405180910390f35b6000806000806019915060649050818193509350505090915600a165627a7a72305820c6501c6222f133f6155ad8a06b1f390eb2ef6e2703245dff2213bb28f3d072ba0029"
	reserveCode := "0x60806040526000600355336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550612c87806100586000396000f3006080604052600436106100f1576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063158ef93e1461010f57806318ff9d231461013e5780631c39c7d51461017057806345eb9077146101d55780635fa7b58414610230578063617f9dd01461028b5780636bec32da146102b6578063715018a61461033b5780637b103999146103525780638da5cb5b146103a9578063950dad1914610400578063a91ee0dc1461045b578063c4d66de81461049e578063d48bfca7146104e1578063d6b34fd71461053c578063e4860339146105c7578063f2fde38b14610622575b610107600160035461066590919063ffffffff16565b600381905550005b34801561011b57600080fd5b50610124610681565b604051808215151515815260200191505060405180910390f35b34801561014a57600080fd5b50610153610694565b604051808381526020018281526020019250505060405180910390f35b34801561017c57600080fd5b506101bb600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001909291905050506106ae565b604051808215151515815260200191505060405180910390f35b3480156101e157600080fd5b50610216600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610aae565b604051808215151515815260200191505060405180910390f35b34801561023c57600080fd5b50610271600480360381019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919050505061140f565b604051808215151515815260200191505060405180910390f35b34801561029757600080fd5b506102a0611527565b6040518082815260200191505060405180910390f35b3480156102c257600080fd5b50610321600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035906020019092919050505061152d565b604051808215151515815260200191505060405180910390f35b34801561034757600080fd5b506103506119b2565b005b34801561035e57600080fd5b50610367611ab4565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b3480156103b557600080fd5b506103be611ada565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34801561040c57600080fd5b50610441600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050611aff565b604051808215151515815260200191505060405180910390f35b34801561046757600080fd5b5061049c600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050611cf3565b005b3480156104aa57600080fd5b506104df600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050611dd5565b005b3480156104ed57600080fd5b50610522600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050611e58565b604051808215151515815260200191505060405180910390f35b34801561054857600080fd5b506105b1600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035906020019092919080359060200190929190505050611f75565b6040518082815260200191505060405180910390f35b3480156105d357600080fd5b50610608600480360381019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919050505061270e565b604051808215151515815260200191505060405180910390f35b34801561062e57600080fd5b50610663600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050612764565b005b6000818301905082811015151561067857fe5b80905092915050565b600060149054906101000a900460ff1681565b600080600080601991506064905081819350935050509091565b6000806040805190810160405280600781526020017f41756374696f6e00000000000000000000000000000000000000000000000000815250600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16630b5855e1826040518263ffffffff167c01000000000000000000000000000000000000000000000000000000000281526004018080602001828103825283818151815260200191508051906020019080838360005b83811015610791578082015181840152602081019050610776565b50505050905090810190601f1680156107be5780820380516001836020036101000a031916815260200191505b5092505050602060405180830381600087803b1580156107dd57600080fd5b505af11580156107f1573d6000803e3d6000fd5b505050506040513d602081101561080757600080fd5b810190808051906020019092919050505073ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614151561085157600080fd5b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16630b5855e16040805190810160405280600981526020017f476f6c64546f6b656e00000000000000000000000000000000000000000000008152506040518263ffffffff167c01000000000000000000000000000000000000000000000000000000000281526004018080602001828103825283818151815260200191508051906020019080838360005b83811015610930578082015181840152602081019050610915565b50505050905090810190601f16801561095d5780820380516001836020036101000a031916815260200191505b5092505050602060405180830381600087803b15801561097c57600080fd5b505af1158015610990573d6000803e3d6000fd5b505050506040513d60208110156109a657600080fd5b810190808051906020019092919050505091508173ffffffffffffffffffffffffffffffffffffffff1663a9059cbb86866040518363ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050602060405180830381600087803b158015610a5c57600080fd5b505af1158015610a70573d6000803e3d6000fd5b505050506040513d6020811015610a8657600080fd5b81019080805190602001909291905050501515610aa257600080fd5b60019250505092915050565b60008060008060008060008088600260008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff161515610b1357600080fd5b8997508773ffffffffffffffffffffffffffffffffffffffff16639095d94f6040518163ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401602060405180830381600087803b158015610b7a57600080fd5b505af1158015610b8e573d6000803e3d6000fd5b505050506040513d6020811015610ba457600080fd5b81019080805190602001909291905050501515610bc057600080fd5b8773ffffffffffffffffffffffffffffffffffffffff1663147198106040518163ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401600060405180830381600087803b158015610c2457600080fd5b505af1158015610c38573d6000803e3d6000fd5b505050508773ffffffffffffffffffffffffffffffffffffffff166318160ddd6040518163ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401602060405180830381600087803b158015610ca057600080fd5b505af1158015610cb4573d6000803e3d6000fd5b505050506040513d6020811015610cca57600080fd5b810190808051906020019092919050505096508773ffffffffffffffffffffffffffffffffffffffff16637e3e04616040518163ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401602060405180830381600087803b158015610d4157600080fd5b505af1158015610d55573d6000803e3d6000fd5b505050506040513d6020811015610d6b57600080fd5b8101908080519060200190929190505050955085871115610f0b57899450600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16630b5855e16040805190810160405280600981526020017f476f6c64546f6b656e00000000000000000000000000000000000000000000008152506040518263ffffffff167c01000000000000000000000000000000000000000000000000000000000281526004018080602001828103825283818151815260200191508051906020019080838360005b83811015610e68578082015181840152602081019050610e4d565b50505050905090810190601f168015610e955780820380516001836020036101000a031916815260200191505b5092505050602060405180830381600087803b158015610eb457600080fd5b505af1158015610ec8573d6000803e3d6000fd5b505050506040513d6020811015610ede57600080fd5b81019080805190602001909291905050509350610f0486886127cb90919063ffffffff16565b925061108c565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16630b5855e16040805190810160405280600981526020017f476f6c64546f6b656e00000000000000000000000000000000000000000000008152506040518263ffffffff167c01000000000000000000000000000000000000000000000000000000000281526004018080602001828103825283818151815260200191508051906020019080838360005b83811015610fea578082015181840152602081019050610fcf565b50505050905090810190601f1680156110175780820380516001836020036101000a031916815260200191505b5092505050602060405180830381600087803b15801561103657600080fd5b505af115801561104a573d6000803e3d6000fd5b505050506040513d602081101561106057600080fd5b8101908080519060200190929190505050945089935061108987876127cb90919063ffffffff16565b92505b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16630b5855e16040805190810160405280600781526020017f41756374696f6e000000000000000000000000000000000000000000000000008152506040518263ffffffff167c01000000000000000000000000000000000000000000000000000000000281526004018080602001828103825283818151815260200191508051906020019080838360005b8381101561116b578082015181840152602081019050611150565b50505050905090810190601f1680156111985780820380516001836020036101000a031916815260200191505b5092505050602060405180830381600087803b1580156111b757600080fd5b505af11580156111cb573d6000803e3d6000fd5b505050506040513d60208110156111e157600080fd5b810190808051906020019092919050505091508173ffffffffffffffffffffffffffffffffffffffff1663056d380c86866040518363ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200192505050600060405180830381600087803b1580156112c357600080fd5b505af11580156112d7573d6000803e3d6000fd5b505050508173ffffffffffffffffffffffffffffffffffffffff166362edcae886868d876040518563ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001828152602001945050505050600060405180830381600087803b1580156113e657600080fd5b505af11580156113fa573d6000803e3d6000fd5b50505050600198505050505050505050919050565b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614151561146c57600080fd5b81600260008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff1615156114c557600080fd5b6000600260008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006101000a81548160ff0219169083151502179055506001915050919050565b60035481565b60008083600260008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff16151561158957600080fd5b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16630b5855e16040805190810160405280600781526020017f41756374696f6e000000000000000000000000000000000000000000000000008152506040518263ffffffff167c01000000000000000000000000000000000000000000000000000000000281526004018080602001828103825283818151815260200191508051906020019080838360005b8381101561166857808201518184015260208101905061164d565b50505050905090810190601f1680156116955780820380516001836020036101000a031916815260200191505b5092505050602060405180830381600087803b1580156116b457600080fd5b505af11580156116c8573d6000803e3d6000fd5b505050506040513d60208110156116de57600080fd5b810190808051906020019092919050505073ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614806118b85750600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16630b5855e16040805190810160405280600981526020017f426f6e64546f6b656e00000000000000000000000000000000000000000000008152506040518263ffffffff167c01000000000000000000000000000000000000000000000000000000000281526004018080602001828103825283818151815260200191508051906020019080838360005b838110156118025780820151818401526020810190506117e7565b50505050905090810190601f16801561182f5780820380516001836020036101000a031916815260200191505b5092505050602060405180830381600087803b15801561184e57600080fd5b505af1158015611862573d6000803e3d6000fd5b505050506040513d602081101561187857600080fd5b810190808051906020019092919050505073ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16145b15156118c357600080fd5b8491508173ffffffffffffffffffffffffffffffffffffffff166340c10f1987866040518363ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050602060405180830381600087803b15801561196957600080fd5b505af115801561197d573d6000803e3d6000fd5b505050506040513d602081101561199357600080fd5b8101908080519060200190929190505050506001925050509392505050565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16141515611a0d57600080fd5b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff167ff8df31144d9c2f0f6b59d69b8b98abd5459d07f2742c4df920b25aae33c6482060405160405180910390a260008060006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60008082600260008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff161515611b5b57600080fd5b8391508173ffffffffffffffffffffffffffffffffffffffff166342966c688373ffffffffffffffffffffffffffffffffffffffff166370a08231306040518263ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001915050602060405180830381600087803b158015611c1557600080fd5b505af1158015611c29573d6000803e3d6000fd5b505050506040513d6020811015611c3f57600080fd5b81019080805190602001909291905050506040518263ffffffff167c010000000000000000000000000000000000000000000000000000000002815260040180828152602001915050602060405180830381600087803b158015611ca257600080fd5b505af1158015611cb6573d6000803e3d6000fd5b505050506040513d6020811015611ccc57600080fd5b81019080805190602001909291905050501515611ce857600080fd5b600192505050919050565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16141515611d4e57600080fd5b80600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508073ffffffffffffffffffffffffffffffffffffffff167f27fe5f0c1c3b1ed427cc63d0f05759ffdecf9aec9e18d31ef366fc8a6cb5dc3b60405160405180910390a250565b600060149054906101000a900460ff16151515611df157600080fd5b6001600060146101000a81548160ff021916908315150217905550336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550611e5581611cf3565b50565b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16141515611eb557600080fd5b60001515600260008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff161515141515611f1457600080fd5b6001600260008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006101000a81548160ff02191690831515021790555060019050919050565b600080600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16630b5855e16040805190810160405280600981526020017f476f6c64546f6b656e00000000000000000000000000000000000000000000008152506040518263ffffffff167c01000000000000000000000000000000000000000000000000000000000281526004018080602001828103825283818151815260200191508051906020019080838360005b8381101561205757808201518184015260208101905061203c565b50505050905090810190601f1680156120845780820380516001836020036101000a031916815260200191505b5092505050602060405180830381600087803b1580156120a357600080fd5b505af11580156120b7573d6000803e3d6000fd5b505050506040513d60208110156120cd57600080fd5b810190808051906020019092919050505090508073ffffffffffffffffffffffffffffffffffffffff168573ffffffffffffffffffffffffffffffffffffffff161415158173ffffffffffffffffffffffffffffffffffffffff168773ffffffffffffffffffffffffffffffffffffffff161415151415151561214f57600080fd5b600260008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff161515600260008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff161515141515156121fa57600080fd5b612206868686866127e4565b151561221157600080fd5b8073ffffffffffffffffffffffffffffffffffffffff168673ffffffffffffffffffffffffffffffffffffffff161415612450578073ffffffffffffffffffffffffffffffffffffffff166323b872dd3330876040518463ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018281526020019350505050602060405180830381600087803b15801561231c57600080fd5b505af1158015612330573d6000803e3d6000fd5b505050506040513d602081101561234657600080fd5b8101908080519060200190929190505050151561236257600080fd5b8473ffffffffffffffffffffffffffffffffffffffff166340c10f1933856040518363ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050602060405180830381600087803b15801561240557600080fd5b505af1158015612419573d6000803e3d6000fd5b505050506040513d602081101561242f57600080fd5b8101908080519060200190929190505050151561244b57600080fd5b612702565b8573ffffffffffffffffffffffffffffffffffffffff166323b872dd3330876040518463ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018281526020019350505050602060405180830381600087803b15801561252757600080fd5b505af115801561253b573d6000803e3d6000fd5b505050506040513d602081101561255157600080fd5b8101908080519060200190929190505050151561256d57600080fd5b8573ffffffffffffffffffffffffffffffffffffffff166342966c68856040518263ffffffff167c010000000000000000000000000000000000000000000000000000000002815260040180828152602001915050602060405180830381600087803b1580156125dc57600080fd5b505af11580156125f0573d6000803e3d6000fd5b505050506040513d602081101561260657600080fd5b8101908080519060200190929190505050508073ffffffffffffffffffffffffffffffffffffffff1663a9059cbb33856040518363ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050602060405180830381600087803b1580156126bb57600080fd5b505af11580156126cf573d6000803e3d6000fd5b505050506040513d60208110156126e557600080fd5b8101908080519060200190929190505050151561270157600080fd5b5b82915050949350505050565b6000600260008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff169050919050565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161415156127bf57600080fd5b6127c881612acd565b50565b60008282111515156127d957fe5b818303905092915050565b6000806000806127f2612c41565b6127fa612c41565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16630b5855e16040805190810160405280600a81526020017f4d656469616e61746f72000000000000000000000000000000000000000000008152506040518263ffffffff167c01000000000000000000000000000000000000000000000000000000000281526004018080602001828103825283818151815260200191508051906020019080838360005b838110156128d95780820151818401526020810190506128be565b50505050905090810190601f1680156129065780820380516001836020036101000a031916815260200191505b5092505050602060405180830381600087803b15801561292557600080fd5b505af1158015612939573d6000803e3d6000fd5b505050506040513d602081101561294f57600080fd5b810190808051906020019092919050505094508473ffffffffffffffffffffffffffffffffffffffff1663baaa61be8b8b6040518363ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001925050506040805180830381600087803b158015612a3057600080fd5b505af1158015612a44573d6000803e3d6000fd5b505050506040513d6040811015612a5a57600080fd5b810190808051906020019092919080519060200190929190505050809450819550505060408051908101604052808581526020018481525091506040805190810160405280898152602001888152509050612abe8282612bc790919063ffffffff16565b95505050505050949350505050565b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614151515612b0957600080fd5b8073ffffffffffffffffffffffffffffffffffffffff166000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a3806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b6000612be483602001518360000151612c0990919063ffffffff16565b612bff83602001518560000151612c0990919063ffffffff16565b1015905092915050565b600080831415612c1c5760009050612c3b565b8183029050818382811515612c2d57fe5b04141515612c3757fe5b8090505b92915050565b6040805190810160405280600081526020016000815250905600a165627a7a723058203986d161b7f96413d04d2a73d91e42e5c413b1dfc1505ebaeca470fb12245a970029"
	decoded, _ := hexutil.Decode(reserveCode)
	// tobinTaxCode := []byte{96, 128, 96, 64, 82, 96, 4, 54, 16, 96, 63, 87, 96, 0, 53, 124, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 144, 4, 99, 255, 255, 255, 255, 22, 128, 99, 24, 255, 157, 35, 20, 96, 68, 87, 91, 96, 0, 128, 253, 91, 52, 128, 21, 96, 79, 87, 96, 0, 128, 253, 91, 80, 96, 86, 96, 115, 86, 91, 96, 64, 81, 128, 131, 129, 82, 96, 32, 1, 130, 129, 82, 96, 32, 1, 146, 80, 80, 80, 96, 64, 81, 128, 145, 3, 144, 243, 91, 96, 0, 128, 96, 0, 128, 96, 25, 145, 80, 96, 100, 144, 80, 129, 129, 147, 80, 147, 80, 80, 80, 144, 145, 86, 0, 161, 101, 98, 122, 122, 114, 48, 88, 32, 198, 80, 28, 98, 34, 241, 51, 246, 21, 90, 216, 160, 107, 31, 57, 14, 178, 239, 110, 39, 3, 36, 93, 255, 34, 19, 187, 40, 243, 208, 114, 186, 0, 41}

	// Assemble and return the genesis with the precompiles and faucet pre-funded
	return &Genesis{
		Config:     &config,
		ExtraData:  append(append(make([]byte, 52), faucet[:]...), make([]byte, 65)...),
		GasLimit:   6283185,
		Difficulty: big.NewInt(1),
		Alloc: map[common.Address]GenesisAccount{
			common.BytesToAddress([]byte{1}):                                {Balance: big.NewInt(1)}, // ECRecover
			common.BytesToAddress([]byte{2}):                                {Balance: big.NewInt(1)}, // SHA256
			common.BytesToAddress([]byte{3}):                                {Balance: big.NewInt(1)}, // RIPEMD
			common.BytesToAddress([]byte{4}):                                {Balance: big.NewInt(1)}, // Identity
			common.BytesToAddress([]byte{5}):                                {Balance: big.NewInt(1)}, // ModExp
			common.BytesToAddress([]byte{6}):                                {Balance: big.NewInt(1)}, // ECAdd
			common.BytesToAddress([]byte{7}):                                {Balance: big.NewInt(1)}, // ECScalarMul
			common.BytesToAddress([]byte{8}):                                {Balance: big.NewInt(1)}, // ECPairing
			common.HexToAddress("000000000000000000000000000000000000abcd"): {Balance: big.NewInt(100), Code: decoded},
			faucet: {Balance: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(9))},
		},
	}
}

func decodePrealloc(data string) GenesisAlloc {
	var p []struct{ Addr, Balance *big.Int }
	if err := rlp.NewStream(strings.NewReader(data), 0).Decode(&p); err != nil {
		panic(err)
	}
	ga := make(GenesisAlloc, len(p))
	for _, account := range p {
		ga[common.BigToAddress(account.Addr)] = GenesisAccount{Balance: account.Balance}
	}
	return ga
}
