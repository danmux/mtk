package mtk

import (
	"github.com/google/uuid"
)

type Team struct {
	ID          uuid.UUID // unique id for this team
	Name        string    // team name
	MasterNonce Key       // the nonce used to encrypt the master key
	MasterCrypt Key       // the encrypted master key
	PassHash    Key       // to verify the master kpassPhrase
	PassHint    string    // hint to the pass phrase
	People      []*person // the other people making up this team
}

// newTeam creates a team with the given name and master password. It creates
// the named people assigning each a secret key.
func newTeam(name, masterPass, hint string, people []string) (*Team, Key, error) {

	tID := uuid.New()
	teamID := tID[:]
	passBytes := []byte(masterPass)

	master, err := rand128Key()
	if err != nil {
		return nil, nil, err
	}

	nonce, err := newNonce()
	if err != nil {
		return nil, nil, err
	}

	mc, err := gcmEncrypt(passBytes, nonce, master, teamID)
	if err != nil {
		return nil, nil, err
	}

	passHash, err := hash256(teamID, passBytes)
	if err != nil {
		return nil, nil, err
	}

	team := &Team{
		ID:          tID,
		Name:        name,
		MasterNonce: nonce,
		MasterCrypt: mc,
		PassHash:    passHash,
		PassHint:    hint,
	}

	for _, n := range people {
		p, err := newPerson(master, n)
		if err != nil {
			return nil, nil, err
		}
		team.People = append(team.People, p)
	}
	return team, master, nil
}

func (t Team) allKeys(masterPass string) (keys []Key, err error) {
	teamID := t.ID[:]
	masterKey, err := gcmDecrypt(Key(masterPass), t.MasterNonce, t.MasterCrypt, teamID)
	for _, p := range t.People {
		k, err := p.decryptKey(masterKey)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func (t Team) find(name string) (int, *person) {
	for i, p := range t.People {
		if p.Name == name {
			return i, p
		}
	}
	return -1, nil
}

// func (t Team) dumpKeys(w io.Writer, masterPass string) error {
// 	keys, err := t.namedKeys(masterPass)
// 	if err != nil {
// 		return err
// 	}
// 	for _, p := range keys {
// 		w.Write([]byte(p.Name))
// 		w.Write([]byte(" - "))
// 		w.Write([]byte(p.Key))
// 		w.Write([]byte("\n"))
// 	}
// 	return nil
// }

type NamedKey struct {
	Name string
	Key  string
}

func (t Team) NamedKeys(masterPass string) (keys []NamedKey, err error) {
	teamID := t.ID[:]
	masterKey, err := gcmDecrypt(Key(masterPass), t.MasterNonce, t.MasterCrypt, teamID)
	if err != nil {
		return nil, err
	}

	for _, p := range t.People {
		k, err := p.decryptKey(masterKey)
		if err != nil {
			return nil, nil
		}
		keys = append(keys, NamedKey{
			Name: p.Name,
			Key:  k.UserString(),
		})
	}
	return keys, nil
}

type person struct {
	ID       uuid.UUID // the id for this person, and the nonce to encrypt the user key
	Name     string    // the human display name for this person
	Nonce    Key       // the nonce to encrypt the key with
	KeyHash  Key       // a hash to validate a persons key
	KeyCrypt Key       // encrypted key for this person
}

func newPerson(masterKey Key, name string) (*person, error) {
	k, err := rand128Key()
	if err != nil {
		return nil, err
	}

	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}

	p := &person{
		ID:    uuid.New(),
		Name:  name,
		Nonce: nonce,
	}
	personID := []byte(p.ID.String())

	kc, err := gcmEncrypt(masterKey, p.Nonce, k, personID)
	if err != nil {
		return nil, err
	}
	p.KeyCrypt = kc

	passHash, err := hash256(personID, kc)
	if err != nil {
		return nil, err
	}
	p.KeyHash = passHash

	return p, nil
}

func (p *person) decryptKey(masterKey Key) (Key, error) {
	personID := []byte(p.ID.String())
	return gcmDecrypt(masterKey, p.Nonce, p.KeyCrypt, personID)
}
