package p2p

import (
	cfg "github.com/tendermint/go-config"
	"github.com/tendermint/go-crypto"
	gop2p "github.com/tendermint/go-p2p"
	"github.com/tendermint/go-wire"
	"github.com/zballs/pos/crypto/tndr"
	. "github.com/zballs/pos/util"
)

// From github.com/jaekwon/twirl/node/node

const (
	DEFAULT_PROTO = "tcp"
	PART_SIZE     = 1024 * 16
)

// TODO: add logger

type Node struct {
	config      cfg.Config
	dataReactor *DataReactor
	pexReactor  *gop2p.PEXReactor
	priv        crypto.PrivKeyEd25519
	sw          *gop2p.Switch
}

func NewNode(config cfg.Config) *Node {
	password := config.GetString("password")
	priv := tndr.GeneratePrivKey(password)
	// should addrbook path be in config
	// or should we pass it as arg?
	bookPath := config.GetString("addrbook_path")
	book := gop2p.NewAddrBook(bookPath)
	pexReactor := gop2p.NewPEXReactor(book)
	dataReactor := NewDataReactor()
	input := config.GetString("input")
	output := config.GetString("output")
	if input != "" {
		bytes := MustReadFile(input)
		parts, err := NewPartSetFromData(bytes, PART_SIZE)
		Check(err)
		dataReactor.SetParts(parts)
	}
	if output != "" {
		dataReactor.SetOutputPath(output)
	}
	sw := gop2p.NewSwitch(config)
	sw.AddReactor("PEX", pexReactor)
	sw.AddReactor("DATA", dataReactor)
	return &Node{
		dataReactor: dataReactor,
		pexReactor:  pexReactor,
		priv:        priv,
		sw:          sw,
	}
}

func (nd *Node) Start() error {
	ndInfo := newNodeInfo(nd.config, nd.sw, nd.priv)
	nd.sw.SetNodeInfo(ndInfo)
	nd.sw.SetNodePrivKey(nd.priv)
	nd.sw.SetNodePrivKey(nd.priv)
	_, err := nd.sw.Start()
	return err
}

func (nd *Node) Stop() {
	// TODO: gracefully disconnect from peers
	nd.sw.Stop()
}

func (nd *Node) AddListener(lis gop2p.Listener) {
	nd.sw.AddListener(lis)
}

func (nd *Node) DataReactor() *DataReactor {
	return nd.dataReactor
}

func (nd *Node) PexReactor() *gop2p.PEXReactor {
	return nd.pexReactor
}

func (nd *Node) Switch() *gop2p.Switch {
	return nd.sw
}

func newNodeInfo(config cfg.Config, sw *gop2p.Switch, priv crypto.PrivKeyEd25519) *gop2p.NodeInfo {
	ndInfo := &gop2p.NodeInfo{
		Network: config.GetString("network"),
		Version: config.GetString("version"),
		Other: []string{
			Sprintf("wire_version=%v", wire.Version),
			Sprintf("gop2p_version=%v", gop2p.Version),
		},
	}
	if !sw.IsListening() {
		return ndInfo
	}
	lis := sw.Listeners()[0]
	addr := lis.ExternalAddress()
	host := addr.IP.String()
	port := addr.Port
	ndInfo.ListenAddr = Sprintf("%v:%v", host, port)
	return ndInfo
}

func RunNode(config cfg.Config) *Node {
	nd := NewNode(config)
	laddr := config.GetString("node_laddr")
	proto, addr := ProtocolAndAddress(laddr)
	skipUPNP := config.GetBool("skip_upnp")
	lis := gop2p.NewDefaultListener(proto, addr, skipUPNP)
	nd.AddListener(lis)
	if err := nd.Start(); err != nil {
		//..
	}
	if seedString := config.GetString("seeds"); seedString != "" {
		seeds := Split(seedString, ",")
		if lmt := config.GetInt("seeds_limit"); lmt != 0 && len(seeds) > lmt {
			perm := RandPerm(len(seeds))
			_seeds := make([]string, lmt)
			for i, j := range perm[:lmt] {
				_seeds[i] = seeds[j]
			}
			seeds = _seeds
		}
		nd.DialSeeds(seeds)
	}
	return nd
}

func (nd *Node) NodeInfo() *gop2p.NodeInfo {
	return nd.sw.NodeInfo()
}

func (nd *Node) DialSeeds(seeds []string) {
	nd.sw.DialSeeds(seeds)
}

func (nd *Node) ShutdownPeers() {
	msg := new(ShutdownMessage)
	nd.sw.Broadcast(DATA_CHANNEL, struct{ DataMessage }{msg})
}

func ProtocolAndAddress(laddr string) (string, string) {
	proto, addr := DEFAULT_PROTO, laddr
	part1, part2, err := Split2(laddr, "://")
	if err == nil {
		proto, addr = part1, part2
	}
	return proto, addr
}
