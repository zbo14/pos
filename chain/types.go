package chain

import (
	"github.com/tendermint/go-crypto"
	"github.com/zballs/pos/crypto/tndr"
	proto "github.com/zballs/pos/protocol"
	. "github.com/zballs/pos/util"
)

// Following the Spacemint specification..

// Block

type Block struct {
	BlockId      int64         `json:"block_id"`
	SubHash      *SubHash      `json:"hash_sub"`
	SubSignature *SubSignature `json:"signature_sub"`
	SubTx        *SubTx        `json:"tx_sub"`
}

func (b *Block) Serialize() []byte {
	return MarshalJSON(b)
}

func NewBlock(commitProof *proto.CommitProof, prevBlock *Block, priv crypto.PrivKeyEd25519, spaceProof *proto.SpaceProof, txs []*Tx) *Block {
	blockId := prevBlock.BlockId + 1
	subHash := NewSubHash(blockId, commitProof, prevBlock.SubHash, priv, spaceProof)
	subTx := NewSubTx(blockId, txs)
	subSig := NewSubSignature(blockId, prevBlock.SubSignature, priv, subTx)
	return &Block{
		BlockId:      blockId,
		SubHash:      subHash,
		SubSignature: subSig,
		SubTx:        subTx,
	}
}

func GenesisBlock(commitProof *proto.CommitProof, priv crypto.PrivKeyEd25519, spaceProof *proto.SpaceProof, txs []*Tx) *Block {
	blockId := int64(0)
	subHash := NewSubHash(blockId, commitProof, nil, priv, spaceProof) //pass nil ptr to prevSubHash
	subTx := NewSubTx(blockId, txs)
	subSig := NewSubSignature(blockId, nil, priv, subTx) //pass nil ptr to prevSubSignature
	return &Block{
		BlockId:      blockId,
		SubHash:      subHash,
		SubSignature: subSig,
		SubTx:        subTx,
	}
}

type SubHash struct {
	BlockId     int64                   `json:"block_id"`
	CommitProof *proto.CommitProof      `json:"commit_proof"`
	SpaceProof  *proto.SpaceProof       `json:"space_proof"`
	Signature   crypto.SignatureEd25519 `json:"signature"`
}

func (subHash *SubHash) Serialize() []byte {
	if subHash == nil {
		return nil
	}
	return MarshalJSON(subHash)
}

func NewSubHash(blockId int64, commitProof *proto.CommitProof, prevSubHash *SubHash, priv crypto.PrivKeyEd25519, spaceProof *proto.SpaceProof) *SubHash {
	data := prevSubHash.Serialize()
	signature := tndr.Sign(priv, data)
	return &SubHash{
		BlockId:     blockId,
		CommitProof: commitProof,
		SpaceProof:  spaceProof,
		Signature:   signature,
	}
}

type SubSignature struct {
	BlockId      int64                   `json:"block_id"`
	SignatureSig crypto.SignatureEd25519 `json:"signature_sig"`
	SignatureTx  crypto.SignatureEd25519 `json:"signature_tx"`
}

func (subSig *SubSignature) Serialize() []byte {
	if subSig == nil {
		return nil
	}
	return MarshalJSON(subSig)
}

func NewSubSignature(blockId int64, prevSubSig *SubSignature, priv crypto.PrivKeyEd25519, subTx *SubTx) *SubSignature {
	data := prevSubSig.Serialize()
	signatureSig := tndr.Sign(priv, data)
	data = subTx.Serialize()
	signatureTx := tndr.Sign(priv, data)
	return &SubSignature{
		BlockId:      blockId,
		SignatureSig: signatureSig,
		SignatureTx:  signatureTx,
	}
}

type SubTx struct {
	BlockId int64 `json:"block_id"`
	Txs     []*Tx `json:"txs"`
}

func (subTx *SubTx) Serialize() []byte {
	return MarshalJSON(subTx)
}

func NewSubTx(blockId int64, txs []*Tx) *SubTx {
	return &SubTx{
		BlockId: blockId,
		Txs:     txs,
	}
}

// Tx
type Tx struct {
	*TxCommit
	*TxPayment
	*TxPunishment
}

func NewTx(isTx IsTx) (*Tx, error) {
	tx := new(Tx)
	switch isTx.(type) {
	case *TxCommit:
		tx.TxCommit = isTx.(*TxCommit)
	case *TxPayment:
		tx.TxPayment = isTx.(*TxPayment)
	case *TxPunishment:
		tx.TxPunishment = isTx.(*TxPunishment)
	default:
		// shouldn't get here
		return nil, Errorf("Unexpected tx type: %T\n", isTx)
	}
	return tx, nil
}

type IsTx interface {
	IsTx()
}

type TxCommit struct {
	Commit []byte               `json:"commit"`
	PubKey crypto.PubKeyEd25519 `json:"public_key"`
	TxId   int64                `json:"tx_id"`
}

func NewTxCommit(commit []byte, pub crypto.PubKeyEd25519, txId int64) *TxCommit {
	return &TxCommit{
		Commit: commit,
		PubKey: pub,
		TxId:   txId,
	}
}

type TxPayment struct {
	Ins  []*In  `json:"ins"`
	Outs []*Out `json:"outs"`
	TxId int64  `json:"tx_id"`
}

func NewTxPayment(ins []*In, outs []*Out, txId int64) *TxPayment {
	return &TxPayment{
		Ins:  ins,
		Outs: outs,
		TxId: txId,
	}
}

type TxPunishment struct {
	PubKey     crypto.PubKeyEd25519 `json:"public_key"`
	Punishment *Punishment          `json:"punishment"`
	TxId       int64                `json:"tx_id"`
}

func NewTxPunishment(pub crypto.PubKeyEd25519, punishment *Punishment, txId int64) *TxPunishment {
	return &TxPunishment{
		PubKey:     pub,
		Punishment: punishment,
		TxId:       txId,
	}
}

const FINE = 100

type Punishment struct {
	BlockId         int64                `json:"block_id"`
	PubKey          crypto.PubKeyEd25519 `json:"public_key"`
	PunishmentProof *PunishmentProof     `json:"punishment_proof"`
}

func NewPunishment(blockId int64, pub crypto.PubKeyEd25519, proof *PunishmentProof) *Punishment {
	return &Punishment{
		BlockId:         blockId,
		PubKey:          pub,
		PunishmentProof: proof,
	}
}

type PunishmentProof struct {
	Chain1Next   *Block               `json:"chain1_next_block"`
	Chain1Recent *Block               `json:"chain1_recent_block"`
	Chain2Next   *Block               `json:"chain2_next_block"`
	Chain2Recent *Block               `json:"chain2_recent_block"`
	PubKey       crypto.PubKeyEd25519 `json:"public_key"`
}

func NewPunishmentProof(pub crypto.PubKeyEd25519, chain1Next, chain1Recent, chain2Next, chain2Recent *Block) *PunishmentProof {
	return &PunishmentProof{
		Chain1Next:   chain1Next,
		Chain1Recent: chain1Recent,
		Chain2Next:   chain2Next,
		Chain2Recent: chain2Recent,
		PubKey:       pub,
	}
}

func (_ *TxCommit) IsTx()     {}
func (_ *TxPayment) IsTx()    {}
func (_ *TxPunishment) IsTx() {}

type In struct {
	PubKey    crypto.PubKeyEd25519    `json:"public_key"`
	Signature crypto.SignatureEd25519 `json:"signature"` //sig(tx_id, past_tx_id, past_beneficiary, out)
	TxId      int64                   `json:"tx_id"`
}

type InSign struct {
	Outs     []*Out               `json:"out"`
	PastTxId int64                `json:"past_tx_id"`
	Pubkey   crypto.PubKeyEd25519 `json:"public_key"`
	TxId     int64                `json:"tx_id"`
}

func NewInSign(outs []*Out, pastTxId int64, pub crypto.PubKeyEd25519, txId int64) *InSign {
	return &InSign{
		Outs:     outs,
		PastTxId: pastTxId,
		Pubkey:   pub,
		TxId:     txId,
	}
}

func (inSign *InSign) Serialize() []byte {
	return MarshalJSON(inSign)
}

func NewIn(outs []*Out, pastTxId int64, priv crypto.PrivKeyEd25519, pub crypto.PubKeyEd25519, txId int64) *In {
	inSign := NewInSign(outs, pastTxId, pub, txId)
	data := inSign.Serialize()
	signature := tndr.Sign(priv, data)
	return &In{
		PubKey:    pub,
		Signature: signature,
		TxId:      txId,
	}
}

type Out struct {
	PubKey crypto.PubKeyEd25519 `json:"public_key"`
	Value  int64                `json:"value"`
}

func NewOut(pub crypto.PubKeyEd25519, value int64) *Out {
	return &Out{
		PubKey: pub,
		Value:  value,
	}
}
