package mtk

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const (
	delim     = "-"
	padString = "="
	pad       = 8
)

type Key []byte

func rand128Key() (Key, error) {
	k := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, k)
	return k, err
}

func (k Key) UserString() string {
	s, err := keyToHuman128Bits(k)
	if err != nil {
		return err.Error()
	}
	return s
}

func hash256(salt, thing []byte) ([]byte, error) {
	return scrypt.Key([]byte("some password"), salt, 32768, 8, 1, 32)
}

func keyToHuman128Bits(key []byte) (string, error) {
	if len(key) != 16 {
		return "", errors.New("key is the wrong length to make a human readable key")
	}
	str := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)
	num := 7
	bLen := 4
	parts := make([]string, num)
	offset := 0
	for i := 0; i < num; i++ {
		if i == num-1 {
			parts[i] = str[offset:]
		} else {
			parts[i] = str[offset : offset+bLen]
		}
		offset += bLen
	}
	return strings.Join(parts, delim), nil
}

func humanToKey128Bits(human string) ([]byte, error) {
	parts := strings.Split(human, delim)
	b32 := strings.Join(parts, "")

	l := len(b32)
	padCount := (l/pad+1)*pad - l
	b32 = b32 + strings.Repeat(padString, padCount)

	b, err := base32.StdEncoding.DecodeString(b32)
	if err != nil {
		return nil, err
	}
	if len(b) != 16 {
		return nil, errors.New("key produced fro human readable key is the wrong length")
	}
	return b, nil
}

func newNonce() ([]byte, error) {
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

func gcmEncrypt(key Key, nonce, plainText, aditional []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm.Seal(nil, nonce, plainText, aditional), nil
}

func gcmDecrypt(key Key, nonce, cipherText, aditional []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plainText, err := aesgcm.Open(nil, nonce, cipherText, aditional)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}
