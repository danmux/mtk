package mtk

import (
	"errors"
	"sort"

	"github.com/google/uuid"
)

type treasure struct {
	ID       uuid.UUID // the id of this version of the treasure
	KeyOrder []int     // the order of the keys this treasure was encrypted with
	Nonce    Key       // the nonce this version was encrypted with
	Trove    []byte    // the encrypted treasure
}

type casket struct {
	ID       uuid.UUID
	Name     string
	Quorum   int         // min number of people
	Treasure []*treasure // the multiply encrypted treasure
}

func newCasket(name string, quorum int) *casket {
	c := &casket{
		ID:     uuid.New(),
		Name:   name,
		Quorum: quorum,
	}

	return c
}

// encrypt takes the set of keys that forms all qourums and encrypts the payload
// with each combined hashed set of keys
func (c *casket) encrypt(keys []Key, payload []byte) error {

	combined, err := keyCombo(len(keys), c.Quorum)
	if err != nil {
		return err
	}

	for _, mix := range combined {
		// make a nonce for this key combo
		nonce, err := newNonce()
		if err != nil {
			return err
		}

		t := &treasure{
			ID:       uuid.New(),
			KeyOrder: mix,
			Nonce:    nonce,
		}

		// make the 256 bit hash of this combined set of keys
		// using the casket id as the salt
		treasureKey, err := c.makeCombinedKey(keys, mix)
		if err != nil {
			return err
		}

		trove, err := gcmEncrypt(treasureKey, nonce, payload, t.ID[:])
		if err != nil {
			return err
		}
		t.Trove = trove
		c.Treasure = append(c.Treasure, t)
	}

	return nil
}

func (c *casket) makeCombinedKey(keys []Key, mix []int) (Key, error) {
	// combine the mix of keys
	var combined Key
	for _, ki := range mix {
		combined = append(combined, keys[ki]...)
	}
	// and hash to 256 bits
	return hash256(c.ID[:], combined)
}

func (c *casket) decrypt(keys []Key, mix []int) ([]byte, error) {

	// make the key
	key, err := c.makeCombinedKey(keys, mix)
	if err != nil {
		return nil, err
	}

	// find this treasure for the given quorum
	t := c.findTreasure(mix)
	if t == nil {
		return nil, errors.New("could not find this combination of keys")
	}

	plain, err := gcmDecrypt(key, t.Nonce, t.Trove, t.ID[:])
	if err != nil {
		return nil, err
	}

	return plain, nil
}

func (c *casket) findTreasure(order []int) *treasure {
	sort.Ints(order)
	for _, t := range c.Treasure {
		if sliceEq(t.KeyOrder, order) {
			return t
		}
	}
	return nil
}

func sliceEq(a, b []int) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func keyCombo(tot int, min int) ([][]int, error) {
	if min > tot {
		return nil, errors.New("min number of keys is more than keys supplied")
	}
	var res [][]int

	if min < 2 {
		for i := 0; i < tot; i++ {
			res = append(res, []int{i})
		}
		return res, nil
	}

	combination(tot, min, func(nums []int) {
		n := make([]int, len(nums))
		copy(n, nums)
		res = append(res, n)
	})

	return res, nil
}

func combination(n, m int, emit func([]int)) {
	s := make([]int, m)
	last := m - 1
	var rc func(int, int)
	rc = func(i, next int) {
		for j := next; j < n; j++ {
			s[i] = j
			if i == last {
				emit(s)
			} else {
				rc(i+1, j+1)
			}
		}
		return
	}
	rc(0, 0)
}
