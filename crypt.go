package mtk

import "errors"

// Crypt is a store of Caskets and their Keepers
type Crypt struct {
	Keepers *Team
	Caskets map[string]*casket
}

// NewCrypt returns a new Crypt with the passed in team
func NewCrypt(name, masterPass, hint string, keepers []string) (*Crypt, Key, error) {
	team, masterKey, err := newTeam(name, masterPass, hint, keepers)
	if err != nil {
		return nil, nil, err
	}
	return &Crypt{
		Keepers: team,
		Caskets: map[string]*casket{},
	}, masterKey, nil
}

// AddCasket adds a casket that encrypts the given content with the
// specified quorum of the receivers Keepers.
func (c *Crypt) AddCasket(casketName, masterPass string, quorum int, content []byte) error {

	keys, err := c.Keepers.allKeys(masterPass)
	if err != nil {
		return err
	}

	casket := newCasket(casketName, quorum)
	err = casket.encrypt(keys, content)
	if err != nil {
		return err
	}

	c.Caskets[casketName] = casket

	return nil
}

// Decrypt hopes to reveal the content of the named casket, given the set of
// supplied named keys
func (c *Crypt) Decrypt(casketName string, keys ...NamedKey) ([]byte, error) {

	casket, ok := c.Caskets[casketName]
	if !ok {
		return nil, errors.New("casket not found")
	}

	l := len(keys)
	if l != casket.Quorum {
		return nil, errors.New("not enough keys to form a quorum")
	}

	// the supplied keys in the same order as our keepers
	origKeys := make([]Key, len(c.Keepers.People))

	// get name mixture
	mix := make([]int, l)
	for i, k := range keys {
		ps, _ := c.Keepers.find(k.Name)
		mix[i] = ps
		tk, err := humanToKey128Bits(k.Key)
		if err != nil {
			return nil, err
		}
		origKeys[ps] = tk
	}

	return casket.decrypt(origKeys, mix)
}
