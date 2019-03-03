package main

import (
	"fmt"

	"github.com/danmux/mtk"
)

func main() {

	masterPass := "silly password 4"
	people := []string{"ruth", "oscar", "phoebe", "fergus"}
	crypt, masterKey, err := mtk.NewCrypt("mulls", masterPass, "none obvious hint", people)
	if err != nil {
		panic(err)
	}

	// this is the master key to define this crpyt
	// this key is inherent in the file, and would only need to be saved
	// if the crypt file is stored remotely - this could be a good file name/key
	fmt.Println(masterKey.UserString())

	pl := []byte("the secret to all my debt")
	casketName := "1Password details"
	err = crypt.AddCasket("1Password details", masterPass, 3, pl)
	if err != nil {
		panic(err)
	}

	// test decrypting - first recover the named keys for the crypt.
	keys, err := crypt.Keepers.NamedKeys(masterPass)
	if err != nil {
		panic(err)
	}

	plain, err := crypt.Decrypt(casketName, keys[3], keys[1], keys[2])
	if err != nil {
		panic(err)
	}

	fmt.Println(string(plain))
}
