package backend

import (
	"bytes"

	blscrypto "github.com/tmptmptmp53451/celo-blockchain/crypto/bls"

	"github.com/tmptmptmp53451/celo-blockchain/common"
	"github.com/tmptmptmp53451/celo-blockchain/consensus/istanbul"
	"github.com/tmptmptmp53451/celo-blockchain/core"
	"github.com/tmptmptmp53451/celo-blockchain/core/types"
	"github.com/tmptmptmp53451/celo-blockchain/rlp"
)

func AppendValidatorsToGenesisBlock(genesis *core.Genesis, validators []istanbul.ValidatorData) {
	if len(genesis.ExtraData) < types.IstanbulExtraVanity {
		genesis.ExtraData = append(genesis.ExtraData, bytes.Repeat([]byte{0x00}, types.IstanbulExtraVanity)...)
	}
	genesis.ExtraData = genesis.ExtraData[:types.IstanbulExtraVanity]

	addrs := []common.Address{}
	publicKeys := []blscrypto.SerializedPublicKey{}

	for i := range validators {
		if (validators[i].BLSPublicKey == blscrypto.SerializedPublicKey{}) {
			panic("BLSPublicKey is nil")
		}
		addrs = append(addrs, validators[i].Address)
		publicKeys = append(publicKeys, validators[i].BLSPublicKey)
	}

	ist := &types.IstanbulExtra{
		AddedValidators:           addrs,
		AddedValidatorsPublicKeys: publicKeys,
		Seal:                      []byte{},
		AggregatedSeal:            types.IstanbulAggregatedSeal{},
		ParentAggregatedSeal:      types.IstanbulAggregatedSeal{},
	}

	istPayload, err := rlp.EncodeToBytes(&ist)
	if err != nil {
		panic("failed to encode istanbul extra")
	}
	genesis.ExtraData = append(genesis.ExtraData, istPayload...)
}
