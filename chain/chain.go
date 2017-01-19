package chain

import (
	"encoding/json"
	"github.com/pkg/errors"
	. "github.com/zballs/pos/util"
	"os"
)

type Chain struct {
	ends Int64s
	file *os.File
}

func NewChain(path string) (*Chain, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &Chain{
		file: file,
	}, nil
}

func (c *Chain) Write(b *Block) error {
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	n, err := c.file.Write(data)
	if err != nil {
		return err
	} else if n != len(data) {
		return errors.New("Couldn't write entire block")
	}
	end := int64(len(data))
	if numBlocks := len(c.ends); numBlocks > 0 {
		end += c.ends[numBlocks-1]
	}
	c.ends = append(c.ends, end)
	return nil
}

func (c *Chain) Read(i int) (*Block, error) {
	if i < 0 {
		return nil, errors.New("i cannot be less than zero")
	}
	var begin, end int64
	if i > 0 {
		begin = c.ends[i-1]
	}
	if i < len(c.ends) {
		end = c.ends[i]
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
	} else if n != len(data) {
		return nil, errors.New("Couldn't read entire block")
	}
	b := new(Block)
	if err = json.Unmarshal(data, b); err != nil {
		return nil, err
	}
	return b, nil
}
