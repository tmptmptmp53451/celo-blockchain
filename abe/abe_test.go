// Copyright 2017 The go-ethereum Authors
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

package abe

import (
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

// func createVerificationMessage(request types.VerificationRequest, account accounts.Account, wallet accounts.Wallet) (string, error) {
// 	signature, err := wallet.SignHash(account, request.UnsignedMessageHash.Bytes())
// 	if err != nil {
// 		return "", err
// 	}
// 	return fmt.Sprintf("Celo verification code: %s:%d", base64.URLEncoding.EncodeToString(signature), request.VerificationIndex), nil
// }
func TestCreateVerificationMessage(t *testing.T) {
	// var request types.VerificationRequest
	request := types.VerificationRequest{}
	log.Error("[Celo] Failed to get account for sms verification", "err", request)
	// if request.PhoneHash {
	// 	t.Error("expected err, got: nil")
	// }
}
