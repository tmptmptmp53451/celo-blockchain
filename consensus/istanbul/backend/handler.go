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

package backend

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/istanbul"
	"github.com/ethereum/go-ethereum/p2p"
	lru "github.com/hashicorp/golang-lru"
)

const (
	istanbulMsg = 0x11
)

var (
	// errDecodeFailed is returned when decode message fails
	errDecodeFailed = errors.New("fail to decode istanbul message")
)

// Protocol implements consensus.Engine.Protocol
func (sb *Backend) Protocol() consensus.Protocol {
	return consensus.Protocol{
		Name:     "istanbul",
		Versions: []uint{64},
		Lengths:  []uint64{18},
	}
}

// HandleMsg implements consensus.Handler.HandleMsg
func (sb *Backend) HandleMsg(addr common.Address, msg p2p.Msg) (bool, error) {
	if msg.Code == istanbulMsg {

		var data []byte
		if err := msg.Decode(&data); err != nil {
			return true, errDecodeFailed
		}

		hash := istanbul.RLPHash(data)

		if !sb.coreStarted {
			return true, istanbul.ErrStoppedEngine
		}

		// Mark peer's message
		ms, ok := sb.recentMessages.Get(addr)
		var m *lru.ARCCache
		if ok {
			m, _ = ms.(*lru.ARCCache)
		} else {
			sb.recentMessagesMu.Lock()
			ms, ok := sb.recentMessages.Get(addr)
			if ok {
				m, _ = ms.(*lru.ARCCache)
			} else {
				m, _ = lru.NewARC(inmemoryMessages)
				sb.recentMessages.Add(addr, m)
			}
			sb.recentMessagesMu.Unlock()
		}
		m.Add(hash, true)

		sb.knownMessagesMu.Lock()
		// Mark self known message
		if sb.knownMessages.Contains(hash) {
			return true, nil
		}
		sb.knownMessages.Add(hash, true)
		sb.knownMessagesMu.Unlock()

		if !msg.ReceivedAt.IsZero() {
			sb.istanbulMsgPuttingInQueueTimer.UpdateSince(msg.ReceivedAt)
		}

		go sb.istanbulEventMux.PostWOLock(istanbul.MessageEvent{
			Payload:    data,
			ReceivedAt: msg.ReceivedAt,
		})

		return true, nil
	}
	return false, nil
}

// SetBroadcaster implements consensus.Handler.SetBroadcaster
func (sb *Backend) SetBroadcaster(broadcaster consensus.Broadcaster) {
	sb.broadcaster = broadcaster
}

func (sb *Backend) NewChainHead() error {
	sb.coreMu.RLock()
	defer sb.coreMu.RUnlock()
	if !sb.coreStarted {
		return istanbul.ErrStoppedEngine
	}
	go sb.istanbulEventMux.Post(istanbul.FinalCommittedEvent{})
	return nil
}
