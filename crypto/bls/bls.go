package blscrypto

import (
	"crypto/ecdsa"
)

const (
	PUBLICKEYBYTES = 96
	SIGNATUREBYTES = 48
)

type SerializedPublicKey [PUBLICKEYBYTES]byte
type SerializedSignature [SIGNATUREBYTES]byte

func ECDSAToBLS(privateKeyECDSA *ecdsa.PrivateKey) ([]byte, error) {
	panic("not implemented")
}

func PrivateToPublic(privateKeyBytes []byte) (SerializedPublicKey, error) {
	panic("not implemented")
}

func VerifyAggregatedSignature(publicKeys []SerializedPublicKey, message []byte, extraData []byte, signature []byte, shouldUseCompositeHasher bool) error {
	panic("not implemented")
}

func AggregateSignatures(signatures [][]byte) ([]byte, error) {
	panic("not implemented")
}

func VerifySignature(publicKey SerializedPublicKey, message []byte, extraData []byte, signature []byte, shouldUseCompositeHasher bool) error {
	panic("not implemented")
}

func EncodeEpochSnarkData(newValSet []SerializedPublicKey, maximumNonSignersPlusOne uint32, epochIndex uint16) ([]byte, error) {
	panic("not implemented")
}

func SerializedSignatureFromBytes(serializedSignature []byte) (SerializedSignature, error) {
	panic("not implemented")
}
