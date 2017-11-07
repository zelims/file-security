package main

import (
	"io/ioutil"
	"log"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"errors"
	"crypto/rand"
	"os"
)

func main() {
	args := os.Args[1:]
	if len(os.Args) < 3 {
		log.Printf("[Argument Error] %s %s %s %s", os.Args[0], "enc/dec", "src", "out")
		return
	}
	if args[0] == "encrypt" || args[0] == "enc" {
		data, _ := ioutil.ReadFile(args[1])
		enc, _ := Encrypt(data)
		ioutil.WriteFile(args[2], enc, 0600)
		log.Printf("[*] Encrypted %s", args[1])
	}else if args[0] == "decrypt" || args[0] == "dec" {
		fileCont, _ := ioutil.ReadFile(args[1])
		decrypted, _ := Decrypt(fileCont)
		ioutil.WriteFile(args[2], decrypted, 0600)
		log.Printf("[*] Decrypted %s", args[1])
	}
}

var key []byte = []byte("RANDOM KEY HERE")

func Encrypt(text []byte) (ciphertext []byte, err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(key); err != nil {
		return nil, err
	}
	ciphertext = make([]byte, aes.BlockSize+len(string(text)))
	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], text)
	return
}

func Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(key); err != nil {
		return
	}
	if len(ciphertext) < aes.BlockSize {
		err = errors.New("ciphertext too short")
		return
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(ciphertext, ciphertext)
	plaintext = ciphertext
	return
}