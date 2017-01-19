package chain

import (
	"encoding/json"
	"github.com/zballs/pos"
	"github.com/zballs/pos/crypto"
	. "github.com/zballs/pos/util"
)

// Following the Spacemint specification..

// Block

type Block struct {
	SubHash      *SubHash      `json:"hash_sub"`
	SubSignature *SubSignature `json:"signature_sub"`
	SubTx        *SubTx        `json:"tx_sub"`
}

func NewBlock(blockId int64, prevBlock *Block, priv *crypto.PrivateKey, spaceProof *pos.SpaceProof, txs []Tx) *Block {
	subHash := NewSubHash(blockId, prevBlock.SubHash, priv, spaceProof)
	subTx := NewSubTx(blockId, txs)
	subSig := NewSubSignature(blockId, prevBlock.SubSignature, priv, subTx)
	return &Block{
		SubHash:      subHash,
		SubSignature: subSig,
		SubTx:        subTx,
	}
}

type SubHash struct {
	BlockId    int64             `json:"block_id"`
	SpaceProof *pos.SpaceProof   `json:"space_proof"`
	Signature  *crypto.Signature `json:"signature"`
}

func (subHash *SubHash) Serialize() []byte {
	data, err := json.Marshal(subHash)
	Check(err)
	return data
}

func NewSubHash(blockId int64, prevSubHash *SubHash, priv *crypto.PrivateKey, spaceProof *pos.SpaceProof) *SubHash {
	data := prevSubHash.Serialize()
	signature := priv.Sign(data)
	return &SubHash{
		BlockId:    blockId,
		SpaceProof: spaceProof,
		Signature:  signature,
	}
}

type SubSignature struct {
	BlockId      int64             `json:"block_id"`
	SignatureSig *crypto.Signature `json:"signature_sig"`
	SignatureTx  *crypto.Signature `json:"signature_tx"`
}

func (subSig *SubSignature) Serialize() []byte {
	data, err := json.Marshal(subSig)
	Check(err)
	return data
}

func NewSubSignature(blockId int64, prevSubSig *SubSignature, priv *crypto.PrivateKey, subTx *SubTx) *SubSignature {
	data := prevSubSig.Serialize()
	signatureSig := priv.Sign(data)
	data = subTx.Serialize()
	signatureTx := priv.Sign(data)
	return &SubSignature{
		BlockId:      blockId,
		SignatureSig: signatureSig,
		SignatureTx:  signatureTx,
	}
}

type SubTx struct {
	BlockId int64 `json:"block_id"`
	Txs     []Tx  `json:"txs"`
}

func (subTx *SubTx) Serialize() []byte {
	data, err := json.Marshal(subTx)
	Check(err)
	return data
}

func NewSubTx(blockId int64, txs []Tx) *SubTx {
	return &SubTx{
		BlockId: blockId,
		Txs:     txs,
	}
}

// Tx
type Tx interface {
	IsTx()
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

type TxCommitment struct {
	Commitment *pos.Commitment   `json:"commitment"`
	PubKey     *crypto.PublicKey `json:"public_key"`
	TxId       int64             `json:"tx_id"`
}

func NewTxCommitment(commitment *pos.Commitment, pub *crypto.PublicKey, txId int64) *TxCommitment {
	return &TxCommitment{
		Commitment: commitment,
		PubKey:     pub,
		TxId:       txId,
	}
}

type TxPunishment struct{}

func (_ *TxPayment) IsTx()    {}
func (_ *TxCommitment) IsTx() {}
func (_ *TxPunishment) IsTx() {}

type In struct {
	PubKey    *crypto.PublicKey `json:"public_key"`
	Signature *crypto.Signature `json:"signature"` //sig(tx_id, past_tx_id, past_beneficiary, out)
	TxId      int64             `json:"tx_id"`
}

type InSign struct {
	Outs     []*Out            `json:"out"`
	PastTxId int64             `json:"past_tx_id"`
	Pubkey   *crypto.PublicKey `json:"public_key"`
	TxId     int64             `json:"tx_id"`
}

func NewInSign(outs []*Out, pastTxId int64, pub *crypto.PublicKey, txId int64) *InSign {
	return &InSign{
		Outs:     outs,
		PastTxId: pastTxId,
		Pubkey:   pub,
		TxId:     txId,
	}
}

func (inSign *InSign) Serialize() []byte {
	data, err := json.Marshal(inSign)
	Check(err)
	return data
}

func NewIn(outs []*Out, pastTxId int64, priv *crypto.PrivateKey, pub *crypto.PublicKey, txId int64) *In {
	inSign := NewInSign(outs, pastTxId, pub, txId)
	data := inSign.Serialize()
	signature := priv.Sign(data)
	return &In{
		PubKey:    pub,
		Signature: signature,
		TxId:      txId,
	}
}

type Out struct {
	PubKey *crypto.PublicKey `json:"public_key"`
	Value  int64             `json:"value"`
}

func NewOut(pub *crypto.PublicKey, value int64) *Out {
	return &Out{
		PubKey: pub,
		Value:  value,
	}
}
