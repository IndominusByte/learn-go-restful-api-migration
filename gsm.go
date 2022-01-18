package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
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
	cdn := &Credentials{Key: []byte(gsm.EncryptionKey)}
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
	Key []byte
}

func (c *Credentials) Encrypt(data []byte) (string, error) {
	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return "", err
	}
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func (c *Credentials) Decrypt(encrypted string) ([]byte, error) {
	ciphertext, err := base64.RawURLEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}
