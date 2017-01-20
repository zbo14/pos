package chain

import (
	"github.com/zballs/pos/crypto"
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

func NewBlock(prevBlock *Block, priv *crypto.PrivateKey, space *proto.SpaceProof, txs []Tx) *Block {
	blockId := prevBlock.BlockId + 1
	subHash := NewSubHash(blockId, prevBlock.SubHash, priv, space)
	subTx := NewSubTx(blockId, txs)
	subSig := NewSubSignature(blockId, prevBlock.SubSignature, priv, subTx)
	return &Block{
		BlockId:      blockId,
		SubHash:      subHash,
		SubSignature: subSig,
		SubTx:        subTx,
	}
}

type SubHash struct {
	BlockId    int64             `json:"block_id"`
	SpaceProof *proto.SpaceProof `json:"space_proof"`
	Signature  *crypto.Signature `json:"signature"`
}

func (subHash *SubHash) Serialize() []byte {
	return MarshalJSON(subHash)
}

func NewSubHash(blockId int64, prevSubHash *SubHash, priv *crypto.PrivateKey, space *proto.SpaceProof) *SubHash {
	data := prevSubHash.Serialize()
	signature := priv.Sign(data)
	return &SubHash{
		BlockId:    blockId,
		SpaceProof: space,
		Signature:  signature,
	}
}

type SubSignature struct {
	BlockId      int64             `json:"block_id"`
	SignatureSig *crypto.Signature `json:"signature_sig"`
	SignatureTx  *crypto.Signature `json:"signature_tx"`
}

func (subSig *SubSignature) Serialize() []byte {
	return MarshalJSON(subSig)
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
	return MarshalJSON(subTx)
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
	Commitment *proto.Commitment `json:"commitment"`
	PubKey     *crypto.PublicKey `json:"public_key"`
	TxId       int64             `json:"tx_id"`
}

func NewTxCommitment(commitment *proto.Commitment, pub *crypto.PublicKey, txId int64) *TxCommitment {
	return &TxCommitment{
		Commitment: commitment,
		PubKey:     pub,
		TxId:       txId,
	}
}

type TxPunishment struct {
	PubKey     *crypto.PublicKey `json:"public_key"`
	Punishment *Punishment       `json:"punishment"`
	TxId       int64             `json:"tx_id"`
}

func NewTxPunishment(pub *crypto.PublicKey, punishment *Punishment, txId int64) *TxPunishment {
	return &TxPunishment{
		PubKey:     pub,
		Punishment: punishment,
		TxId:       txId,
	}
}

const FINE = 100

type Punishment struct {
	BlockId         int64             `json:"block_id"`
	PubKey          *crypto.PublicKey `json:"public_key"`
	PunishmentProof *PunishmentProof  `json:"punishment_proof"`
}

func NewPunishment(blockId int64, pub *crypto.PublicKey, proof *PunishmentProof) *Punishment {
	return &Punishment{
		BlockId:         blockId,
		PubKey:          pub,
		PunishmentProof: proof,
	}
}

type PunishmentProof struct {
	Chain1Next   *Block            `json:"chain1_next_block"`
	Chain1Recent *Block            `json:"chain1_recent_block"`
	Chain2Next   *Block            `json:"chain2_next_block"`
	Chain2Recent *Block            `json:"chain2_recent_block"`
	PubKey       *crypto.PublicKey `json:"public_key"`
}

func NewPunishmentProof(pub *crypto.PublicKey, chain1Next, chain1Recent, chain2Next, chain2Recent *Block) *PunishmentProof {
	return &PunishmentProof{
		Chain1Next:   chain1Next,
		Chain1Recent: chain1Recent,
		Chain2Next:   chain2Next,
		Chain2Recent: chain2Recent,
		PubKey:       pub,
	}
}

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
	return MarshalJSON(inSign)
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
