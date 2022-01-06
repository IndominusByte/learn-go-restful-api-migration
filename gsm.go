package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

type gsmData struct {
	Driver          string `json:"driver"`
	EncryptionKey   string `json:"encryption_key"`
	PgTalkUser      string `json:"pg_talk_user"`
	PgTalkPassword  string `json:"pg_talk_password"`
	MasterDsn       string
	MasterDsnNoCred string `json:"master_dsn_no_cred"`
	FileMigration   string `json:"file_migration"`
}

func (gsm *gsmData) loadFromGsm() error {
	filename := fmt.Sprintf("./conf/data.%s.json", os.Getenv("BACKEND_STAGE"))
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	err = json.NewDecoder(f).Decode(gsm)
	if err != nil {
		return err
	}

	// decode data
	cdn := &Credentials{Key: gsm.EncryptionKey}
	pgtalkuser, pgtalkusererr := cdn.Decrypt(gsm.PgTalkUser)
	if pgtalkusererr != nil {
		return err
	}

	pgtalkpassword, pgtalkpassworderr := cdn.Decrypt(gsm.PgTalkPassword)
	if pgtalkpassworderr != nil {
		return pgtalkpassworderr
	}

	gsm.MasterDsn = fmt.Sprintf(gsm.MasterDsnNoCred, pgtalkuser, pgtalkpassword)

	return nil
}

type Credentials struct {
	Key string
}

func (c *Credentials) Encrypt(text string) (string, error) {
	key, err := hex.DecodeString(c.Key)
	if err != nil {
		return "", err
	}
	plaintext := []byte(text)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.
	return fmt.Sprintf("%x", ciphertext), nil
}

func (c *Credentials) Decrypt(text string) (string, error) {
	key, err := hex.DecodeString(c.Key)
	if err != nil {
		return "", err
	}

	ciphertext, err := hex.DecodeString(text)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext), nil
}
