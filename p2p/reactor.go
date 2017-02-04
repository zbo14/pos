package p2p

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	gop2p "github.com/tendermint/go-p2p"
	"github.com/tendermint/go-wire"
	. "github.com/zbo14/pos/util"
	"sync"
	"time"
)

// From github.com/jaekwon/twirl/node/data_reactor

const (
	// Channels
	DATA_CHANNEL byte = 0x20

	PEER_STATE_KEY           = "peer_state"
	MAX_MESSAGE_SIZE         = 1024 * 100 // 100KB
	BROADCAST_SLEEP_DURATION = 2 * time.Second
	GOSSIP_SLEEP_DURATION    = 100 * time.Millisecond
)

type DataReactor struct {
	gop2p.BaseReactor
	header     PartSetHeader
	mtx        sync.RWMutex
	outputPath string
	parts      *PartSet
}

func NewDataReactor() *DataReactor {
	reactor := new(DataReactor)
	reactor.BaseReactor = *gop2p.NewBaseReactor(nil, "DataReactor", reactor)
	return reactor
}

func (reactor *DataReactor) OnStart() error {
	if err := reactor.BaseReactor.OnStart(); err != nil {
		return err
	}
	go reactor.broadcastRoutine()
	return nil
}

func (reactor *DataReactor) OnStop() {
	reactor.BaseReactor.OnStop()
}

func (reactor *DataReactor) GetPartsHeader() PartSetHeader {
	reactor.mtx.RLock()
	defer reactor.mtx.RUnlock()
	return reactor.header
}

func (reactor *DataReactor) SetPartsHeader(header PartSetHeader) bool {
	reactor.mtx.Lock()
	defer reactor.mtx.Unlock()
	if !reactor.header.IsZero() {
		return false
	}
	reactor.parts = NewPartSetFromHeader(header)
	reactor.header = header
	return true
}

func (reactor *DataReactor) GetParts() *PartSet {
	reactor.mtx.RLock()
	defer reactor.mtx.RUnlock()
	return reactor.parts
}

func (reactor *DataReactor) SetParts(parts *PartSet) bool {
	reactor.mtx.Lock()
	defer reactor.mtx.Unlock()
	if reactor.parts != nil {
		return false
	}
	reactor.header = parts.Header()
	reactor.parts = parts
	return true
}

func (reactor *DataReactor) GetOutputPath() string {
	reactor.mtx.RLock()
	defer reactor.mtx.RUnlock()
	return reactor.outputPath
}

func (reactor *DataReactor) SetOutputPath(path string) {
	reactor.mtx.Lock()
	defer reactor.mtx.Unlock()
	reactor.outputPath = path
}

func (reactor *DataReactor) GetChannels() []*gop2p.ChannelDescriptor {
	return []*gop2p.ChannelDescriptor{
		&gop2p.ChannelDescriptor{
			ID:                DATA_CHANNEL,
			Priority:          5,
			SendQueueCapacity: 100,
		},
	}
}

// Implements Reactor

func (reactor *DataReactor) AddPeer(peer *gop2p.Peer) {
	if !reactor.IsRunning() {
		return
	}
	peerState := NewPeerState(peer)
	peer.Data.Set(PEER_STATE_KEY, peerState)
	go reactor.gossipRoutine(peer, peerState)
}

func (reactor *DataReactor) RemovePeer(peer *gop2p.Peer, reason interface{}) {
	if !reactor.IsRunning() {
		return
	}
	value := peer.Data.Get(PEER_STATE_KEY)
	peerState := value.(*PeerState)
	peerState.Disconnect()
}

func (reactor *DataReactor) Receive(chID byte, src *gop2p.Peer, msgBytes []byte) {
	if !reactor.IsRunning() {
		return
	}
	_, msg, err := DecodeMessage(msgBytes)
	if err != nil {
		// TODO: punish peer
		return
	}
	value := src.Data.Get(PEER_STATE_KEY)
	peerState := value.(*PeerState)
	peerState.SentMessage(msg)
	switch msg := msg.(type) {
	case *PartsHeaderMessage:
		if reactor.GetPartsHeader().IsZero() {
			reactor.SetPartsHeader(msg.Header)
		}
	case *PartMessage:
		if parts := reactor.GetParts(); parts != nil {
			added, _ := parts.AddPart(msg.Part)
			if added {
				msg := &HasPartMessage{msg.Part.Idx}
				reactor.Switch.Broadcast(DATA_CHANNEL, struct{ DataMessage }{msg})
			}
			if added && parts.IsComplete() {
				reader := parts.GetReader()
				data := MustReadAll(reader)
				outputPath := reactor.GetOutputPath()
				MustWriteFile(outputPath, data, 0644)
			}
		}
	case *ShutdownMessage:
		Exit("shutting down..")
	default:
		//unknown message type
	}
}

func (reactor *DataReactor) broadcastRoutine() {
	for reactor.IsRunning() {
		header := reactor.GetPartsHeader()
		if !header.IsZero() {
			msg := &PartsHeaderMessage{header}
			reactor.Switch.Broadcast(DATA_CHANNEL, struct{ DataMessage }{msg})
		}
		parts := reactor.GetParts()
		if parts != nil {
			hasParts := parts.Bits()
			msg := &HasPartsMessage{hasParts}
			reactor.Switch.Broadcast(DATA_CHANNEL, struct{ DataMessage }{msg})
		}
		time.Sleep(BROADCAST_SLEEP_DURATION)
	}
}

func (reactor *DataReactor) gossipRoutine(peer *gop2p.Peer, peerState *PeerState) {
	for peer.IsRunning() && reactor.IsRunning() {
		hasParts := peerState.GetHasParts()
		if hasParts != nil {
			numParts := reactor.parts.Bits().Size()
			buf := make([]byte, 8)
			rand.Read(buf)
			i, _ := binary.Varint(buf)
			if i < 0 {
				i *= -1
			}
			pick := int(i) % numParts
			part := reactor.parts.GetPart(pick)
			msg := &PartMessage{part}
			if peer.TrySend(DATA_CHANNEL, struct{ DataMessage }{msg}) {
				peerState.SetHasPart(pick)
				continue
			}
		}
		time.Sleep(GOSSIP_SLEEP_DURATION)
	}
}

// Peer State
type PeerState struct {
	hasParts BitArray
	mtx      sync.RWMutex
	Peer     *gop2p.Peer
}

func NewPeerState(peer *gop2p.Peer) *PeerState {
	return &PeerState{
		Peer: peer,
	}
}

func (peerState *PeerState) Disconnect() bool {
	return peerState.Peer.Stop()
}

func (peerState *PeerState) SentMessage(msg DataMessage) {
	peerState.mtx.Lock()
	defer peerState.mtx.Unlock()
	switch msg := msg.(type) {
	case *PartsHeaderMessage:
		//ignore
	case *HasPartsMessage:
		peerState.hasParts = msg.HasParts
	case *HasPartMessage:
		if set := peerState.hasParts.Set(msg.Idx); !set {
			//..
		}
	case *PartMessage:
		idx := msg.Part.Idx
		if set := peerState.hasParts.Set(idx); !set {
			//..
		}
	default:
		//unknown message type
	}
}

func (peerState *PeerState) GetHasParts() BitArray {
	peerState.mtx.RLock()
	defer peerState.mtx.RUnlock()
	return peerState.hasParts
}

func (peerState *PeerState) SetHasPart(idx int) bool {
	peerState.mtx.Lock()
	defer peerState.mtx.Unlock()
	if set := peerState.hasParts.Set(idx); !set {
		//..
	}
	return true
}

// Messages
const (
	// PEX
	PARTS_HEADER byte = 0x01
	HAS_PARTS    byte = 0x02
	HAS_PART     byte = 0x03
	PART         byte = 0x04
	SHUTDOWN     byte = 0x05
)

type DataMessage interface{}

var _ = wire.RegisterInterface(
	struct{ DataMessage }{},
	wire.ConcreteType{&PartsHeaderMessage{}, PARTS_HEADER},
	wire.ConcreteType{&HasPartsMessage{}, HAS_PARTS},
	wire.ConcreteType{&HasPartMessage{}, HAS_PART},
	wire.ConcreteType{&PartMessage{}, PART},
	wire.ConcreteType{&ShutdownMessage{}, SHUTDOWN},
)

func DecodeMessage(bz []byte) (byte, DataMessage, error) {
	msgType := bz[0]
	n, err := new(int), new(error)
	reader := bytes.NewReader(bz)
	msg := wire.ReadBinary(struct{ DataMessage }{}, reader, MAX_MESSAGE_SIZE, n, err)
	return msgType, msg, *err
}

type PartsHeaderMessage struct {
	Header PartSetHeader
}

type HasPartsMessage struct {
	HasParts BitArray
}

type HasPartMessage struct {
	Idx int
}

type PartMessage struct {
	Part *Part
}

type ShutdownMessage struct{}
