package chain

import (
	. "github.com/zballs/pos/util"
	"os"
)

type Chain struct {
	ends Int64s
	file *os.File
}

func NewChain(chainPath string) *Chain {
	file := MustCreateFile(chainPath)
	return &Chain{
		file: file,
	}
}

func (c *Chain) Last() int {
	return len(c.ends) - 1
}

func (c *Chain) Write(b *Block) error {
	data := b.Serialize()
	n, err := c.file.Write(data)
	if err != nil {
		return err
	} else if size := len(data); n != size {
		return Errorf("Expected to write %d bytes; only wrote %d bytes\n", size, n)
	}
	end := int64(len(data))
	if numBlocks := len(c.ends); numBlocks > 0 {
		end += c.ends[numBlocks-1]
	}
	c.ends = append(c.ends, end)
	return nil
}

func (c *Chain) MustWrite(b *Block) {
	err := c.Write(b)
	Check(err)
}

func (c *Chain) Read(id int) (*Block, error) {
	// id should not overflow int
	if id < 0 {
		return nil, Error("Block id cannot be less than zero")
	}
	var begin, end int64
	if id > 0 {
		begin = c.ends[id-1]
	}
	if id < len(c.ends) {
		end = c.ends[id]
	} else {
		// just set end to file_size
		stat, err := c.file.Stat()
		if err != nil {
			return nil, err
		}
		end = stat.Size()
	}
	data := make([]byte, end-begin)
	n, err := c.file.ReadAt(data, begin)
	if err != nil {
		return nil, err
	} else if size := len(data); n != size {
		return nil, Errorf("Expected to write %d bytes; only wrote %d bytes\n", size, n)
	}
	b := new(Block)
	UnmarshalJSON(data, b)
	return b, nil
}

func (c *Chain) MustRead(id int) *Block {
	b, err := c.Read(id)
	Check(err)
	return b
}
