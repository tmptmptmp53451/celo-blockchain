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

package core

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/istanbul"
	"math/big"
	"sort"
	"strings"
	"sync"
)

// sendNextRoundChange sends the ROUND CHANGE message with current round + 1
func (c *core) sendNextRoundChange() {
	cv := c.currentView()
	c.sendRoundChange(new(big.Int).Add(cv.Round, common.Big1))
}

// sendRoundChange sends the ROUND CHANGE message with the given round
func (c *core) sendRoundChange(round *big.Int) {
	logger := c.logger.New("state", c.state, "cur_round", c.current.Round(), "cur_seq", c.current.Sequence(), "func", "sendRoundChange", "round", round)

	cv := c.currentView()
	if cv.Round.Cmp(round) >= 0 {
		logger.Error("Cannot send out the round change", "current round", cv.Round, "target round", round)
		return
	}

	logger.Debug("sendRoundChange", "current round", cv.Round, "target round", round, "rcs", c.roundChangeSet)

	c.catchUpRound(&istanbul.View{
		// The round number we'd like to transfer to.
		Round:    new(big.Int).Set(round),
		Sequence: new(big.Int).Set(cv.Sequence),
	})

	// Now we have the new round number and sequence number
	cv = c.currentView()
	rc := &istanbul.RoundChange{
		View:                cv,
		PreparedCertificate: c.current.preparedCertificate,
	}

	payload, err := Encode(rc)
	if err != nil {
		logger.Error("Failed to encode ROUND CHANGE", "rc", rc, "err", err)
		return
	}

	c.broadcast(&istanbul.Message{
		Code: istanbul.MsgRoundChange,
		Msg:  payload,
	})
}

func (c *core) handleRoundChangeCertificate(roundChangeCertificate istanbul.RoundChangeCertificate) error {
	logger := c.logger.New("state", c.state, "cur_round", c.current.Round(), "cur_seq", c.current.Sequence(), "func", "handleRoundChangeCertificate")

	if len(roundChangeCertificate.RoundChangeMessages) > c.valSet.Size() || len(roundChangeCertificate.RoundChangeMessages) < 2*c.valSet.F()+1 {
		return errInvalidRoundChangeCertificateNumMsgs
	}

	seen := make(map[common.Address]bool)
	decodedMessages := make([]istanbul.RoundChange, len(roundChangeCertificate.RoundChangeMessages))
	for i, message := range roundChangeCertificate.RoundChangeMessages {
		// Verify message signed by a validator
		data, err := message.PayloadNoSig()
		if err != nil {
			return err
		}

		signer, err := c.validateFn(data, message.Signature)
		if err != nil {
			return err
		}

		if signer != message.Address {
			return errInvalidRoundChangeCertificateMsgSignature
		}

		// Check for duplicate ROUND CHANGE messages
		if seen[signer] {
			return errInvalidRoundChangeCertificateDuplicate
		}
		seen[signer] = true

		// Check that the message is a ROUND CHANGE message
		if istanbul.MsgRoundChange != message.Code {
			return errInvalidRoundChangeCertificateMsgCode
		}

		var roundChange *istanbul.RoundChange
		if err := message.Decode(&roundChange); err != nil {
			logger.Error("Failed to decode ROUND CHANGE in certificate", "err", err)
			return err
		}

		// Verify ROUND CHANGE message is for a proper view
		if err := c.checkMessage(istanbul.MsgRoundChange, roundChange.View); err != nil {
			return errInvalidRoundChangeCertificateMsgView
		}

		decodedMessages[i] = *roundChange
	}

	for i, message := range roundChangeCertificate.RoundChangeMessages {
		_, val := c.valSet.GetByAddress(message.Address)
		// No need to process ROUND CHANGE messages we've seen before.
		if !c.backend.IsKnownMessage(message) {
			err := c.handleDecodedCheckedRoundChange(&message, &decodedMessages[i], val)
			// We want to continue to process ROUND CHANGE messages if they're for future rounds.
			// TODO(asa): Should we just process every message regardless of if there's an error?
			if err != nil && err != errIgnored {
				return err
			}
		}
	}
	return nil
}

func (c *core) handleRoundChange(msg *istanbul.Message, src istanbul.Validator) error {
	idx, _ := c.valSet.GetByAddress(src.Address())
	logger := c.logger.New("state", c.state, "from", src.Address().Hex(), "from_id", idx, "cur_round", c.current.Round(), "cur_seq", c.current.Sequence(), "func", "handleRoundChange")

	// Decode ROUND CHANGE message
	var rc *istanbul.RoundChange
	if err := msg.Decode(&rc); err != nil {
		logger.Error("Failed to decode ROUND CHANGE", "err", err)
		return errInvalidMessage
	}

	if err := c.checkMessage(istanbul.MsgRoundChange, rc.View); err != nil {
		return err
	}

	return c.handleDecodedCheckedRoundChange(msg, rc, src)
}

func (c *core) handleDecodedCheckedRoundChange(msg *istanbul.Message, rc *istanbul.RoundChange, src istanbul.Validator) error {
	logger := c.logger.New("state", c.state, "from", src.Address().Hex(), "cur_round", c.current.Round(), "cur_seq", c.current.Sequence(), "func", "handleDecodedCheckedRoundChange")

	cv := c.currentView()
	roundView := rc.View

	// Handle the PREPARED certificate if present.
	if rc.HasPreparedCertificate() {
		if err := c.handlePreparedCertificate(rc.PreparedCertificate); err != nil {
			// TODO(asa): Should we still accept the round change message without the certificate if this fails?
			return err
		}
	}

	// Add the ROUND CHANGE message to its message set.
	if err := c.roundChangeSet.Add(roundView.Round, msg, src); err != nil {
		logger.Warn("Failed to add round change message", "from", src, "roundView", roundView, "err", err)
		return err
	}

	ffRound := c.roundChangeSet.MaxRound(c.valSet.F() + 1)
	quorumRound := c.roundChangeSet.MaxRound(2*c.valSet.F() + 1)

	logger.Info("handleRoundChange", "msg_round", roundView.Round, "rcs", c.roundChangeSet.String(), "wfRC", c.waitingForRoundChange, "ffRound", ffRound, "quorumRound", quorumRound)

	if quorumRound != nil && (c.waitingForRoundChange || cv.Round.Cmp(quorumRound) < 0) {
		// We've received 2f+1 ROUND CHANGE messages, start a new round immediately.
		c.startNewRound(quorumRound)
		return nil
	}

	// Once we received f+1 ROUND CHANGE messages, those messages form a weak certificate.
	// If our round number is smaller than the certificate's round number, we would
	// try to catch up the round number.
	if c.waitingForRoundChange && ffRound != nil {
		if cv.Round.Cmp(ffRound) < 0 {
			c.sendRoundChange(ffRound)
		}
		return nil
	}

	if cv.Round.Cmp(roundView.Round) < 0 {
		// Only gossip the message with current round to other validators.
		// TODO(tim) This in fact also gossips newer messages -- remove comment when gossip disabled
		return errIgnored
	}

	return nil
}

// ----------------------------------------------------------------------------

func newRoundChangeSet(valSet istanbul.ValidatorSet) *roundChangeSet {
	return &roundChangeSet{
		validatorSet:      valSet,
		msgsForRound:      make(map[uint64]*messageSet),
		latestRoundForVal: make(map[common.Address]uint64),
		mu:                new(sync.Mutex),
	}
}

type roundChangeSet struct {
	validatorSet      istanbul.ValidatorSet
	msgsForRound      map[uint64]*messageSet
	latestRoundForVal map[common.Address]uint64
	mu                *sync.Mutex
}

// Add adds the round and message into round change set
func (rcs *roundChangeSet) Add(r *big.Int, msg *istanbul.Message, src istanbul.Validator) error {
	rcs.mu.Lock()
	defer rcs.mu.Unlock()

	round := r.Uint64()

	if prevLatestRound, ok := rcs.latestRoundForVal[src.Address()]; ok {
		if prevLatestRound > round {
			// Reject as we have an RC for a later round from this validator.
			return errOldMessage
		} else if prevLatestRound < round {
			// Already got an RC for an earlier round from this validator.
			// Forget that and remember this.
			if rcs.msgsForRound[prevLatestRound] != nil {
				rcs.msgsForRound[prevLatestRound].Remove(src.Address())
				if rcs.msgsForRound[prevLatestRound].Size() == 0 {
					delete(rcs.msgsForRound, prevLatestRound)
				}
			}
		}
	}

	rcs.latestRoundForVal[src.Address()] = round

	if rcs.msgsForRound[round] == nil {
		rcs.msgsForRound[round] = newMessageSet(rcs.validatorSet)
	}
	return rcs.msgsForRound[round].Add(msg)
}

// Clear deletes the messages with smaller round
func (rcs *roundChangeSet) Clear(r *big.Int) {
	rcs.mu.Lock()
	defer rcs.mu.Unlock()

	round := r.Uint64()
	for k, rms := range rcs.msgsForRound {
		if rms.Size() == 0 || k < round {
			if rms != nil {
				for _, msg := range rms.Values() {
					if latestRound, ok := rcs.latestRoundForVal[msg.Address]; ok && k == latestRound {
						delete(rcs.latestRoundForVal, msg.Address)
					}
				}
			}
			delete(rcs.msgsForRound, k)
		}
	}
}

// MaxRound returns the max round which the number of messages is equal or larger than threshold
func (rcs *roundChangeSet) MaxRound(threshold int) *big.Int {
	rcs.mu.Lock()
	defer rcs.mu.Unlock()

	// Sort rounds descending
	var sortedRounds []uint64
	for r := range rcs.msgsForRound {
		sortedRounds = append(sortedRounds, r)
	}
	sort.Slice(sortedRounds, func(i, j int) bool { return sortedRounds[i] > sortedRounds[j] })

	acc := 0
	for _, r := range sortedRounds {
		rms := rcs.msgsForRound[r]
		acc += rms.Size()
		if acc >= threshold {
			return new(big.Int).SetUint64(r)
		}
	}

	return nil
}

// getCertificate returns a round change certificate for round r if a quorum (determined by f) of RC messages
// have been received at a round >= r.
func (rcs *roundChangeSet) getCertificate(r *big.Int, f int) (istanbul.RoundChangeCertificate, error) {
	rcs.mu.Lock()
	defer rcs.mu.Unlock()

	round := r.Uint64()

	cumlCount := 0
	for k, rms := range rcs.msgsForRound {
		if k >= round {
			cumlCount += rms.Size()
		}
	}

	if cumlCount <= 2*f {
		return istanbul.RoundChangeCertificate{}, errFailedCreateRoundChangeCertificate
	}

	i := 0
	messages := make([]istanbul.Message, cumlCount)
	for k, rms := range rcs.msgsForRound {
		if k >= round {
			for _, message := range rms.Values() {
				messages[i] = *message
				i++
			}
		}
	}
	return istanbul.RoundChangeCertificate{
		RoundChangeMessages: messages,
	}, nil
}

func (rcs *roundChangeSet) String() string {
	rcs.mu.Lock()
	defer rcs.mu.Unlock()

	msgsForRoundStr := make([]string, 0, len(rcs.msgsForRound))
	for r, rms := range rcs.msgsForRound {
		msgsForRoundStr = append(msgsForRoundStr, fmt.Sprintf("%v: %v", r, rms.String()))
	}

	latestRoundForValStr := make([]string, 0, len(rcs.latestRoundForVal))
	for addr, r := range rcs.latestRoundForVal {
		latestRoundForValStr = append(latestRoundForValStr, fmt.Sprintf("%v: %v", addr.String(), r))
	}

	return fmt.Sprintf("RCS len=%v  By round: {<%v> %v}  By val: {<%v> %v}",
		len(rcs.latestRoundForVal),
		len(rcs.msgsForRound),
		strings.Join(msgsForRoundStr, ", "),
		len(rcs.latestRoundForVal),
		strings.Join(latestRoundForValStr, ", "))
}
