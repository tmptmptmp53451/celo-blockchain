package gold_token

import (
	"math/big"
	"strings"

	"github.com/tmptmptmp53451/celo-blockchain/accounts/abi"
	"github.com/tmptmptmp53451/celo-blockchain/common"
	"github.com/tmptmptmp53451/celo-blockchain/contract_comm"
	"github.com/tmptmptmp53451/celo-blockchain/core/types"
	"github.com/tmptmptmp53451/celo-blockchain/core/vm"
	"github.com/tmptmptmp53451/celo-blockchain/params"
)

const (
	// This is taken from celo-monorepo/packages/protocol/build/<env>/contracts/GoldToken.json
	increaseSupplyABI = `[{
		"constant": false,
		"inputs": [
		  {
			"name": "amount",
			"type": "uint256"
		  }
		],
		"name": "increaseSupply",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
		}]`

	// This is taken from celo-monorepo/packages/protocol/build/<env>/contracts/GoldToken.json
	totalSupplyABI = `[{
		"constant": true,
		"inputs": [],
		"name": "totalSupply",
		"outputs": [
		  {
			"name": "",
			"type": "uint256"
		  }
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	  }]`
)

var (
	increaseSupplyFuncABI, _ = abi.JSON(strings.NewReader(increaseSupplyABI))
	totalSupplyFuncABI, _    = abi.JSON(strings.NewReader(totalSupplyABI))
)

func GetTotalSupply(header *types.Header, state vm.StateDB) (*big.Int, error) {
	var totalSupply *big.Int
	_, err := contract_comm.MakeStaticCall(
		params.GoldTokenRegistryId,
		totalSupplyFuncABI,
		"totalSupply",
		[]interface{}{},
		&totalSupply,
		params.MaxGasForTotalSupply,
		header,
		state,
	)
	return totalSupply, err
}

func IncreaseSupply(header *types.Header, state vm.StateDB, value *big.Int) error {
	_, err := contract_comm.MakeCall(
		params.GoldTokenRegistryId,
		increaseSupplyFuncABI,
		"increaseSupply",
		[]interface{}{value},
		nil,
		params.MaxGasForIncreaseSupply,
		common.Big0,
		header,
		state,
		false,
	)
	return err
}
