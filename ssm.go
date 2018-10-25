package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

type crypto struct {
	method     string
	filename   string
	passphrase string
	output     string
}

func main() {
	os.Exit(realMain())
}

func realMain() int {
	log.SetOutput(ioutil.Discard)

	method := flag.String("method", "", "[encrypt/decrypt]")
	filename := flag.String("filename", "", "[filename]")
	passphrase := flag.String("passphrase", "", "[your passphrase")
	output := flag.String("output", "", "output filename")
	flag.Parse()

	if *method == "" || *filename == "" || *passphrase == "" || *output == "" {
		flag.PrintDefaults()
		return 1
	}

	c := crypto{
		method:     *method,
		filename:   *filename,
		passphrase: *passphrase,
		output:     *output,
	}

	exitCode, err := Run(c)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error executing CLI: %s\n", err.Error())
		return 1
	}

	return exitCode
}

func Run(c crypto) (int, error) {
	if c.method == "encrypt" {
		fmt.Println("Encrypting...")
		c.encrypt()
		fmt.Println("Done.")
	}
	if c.method == "decrypt" {
		fmt.Println("Decrypting...")
		c.decrypt()
		fmt.Println("Done.")
	}
	return 0, nil
}

func (c crypto) encrypt() {
	block, _ := aes.NewCipher([]byte(createHash(c.passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		errorf("gcm: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		errorf("Cannot read bytes: %v", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, c.readFile(), nil)
	c.saveFile(ciphertext)
}

func (c crypto) decrypt() {
	key := []byte(createHash(c.passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		errorf("Cannot create cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		errorf("GCM: %v", err)
	}
	nonceSize := gcm.NonceSize()
	data := c.readFile()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		errorf("Cannot decrypt file: %v", err)
	}
	c.saveFile(plaintext)
}

func (c crypto) readFile() []byte {
	dat, err := ioutil.ReadFile(c.filename)
	if err != nil {
		errorf("Cannot read file: %v", err)
	}
	return dat
}

func (c crypto) saveFile(data []byte) {
	f, err := os.Create(c.output)
	if err != nil {
		errorf("Cannot save file: %v", err)
	}
	defer f.Close()
	save, err := f.Write(data)
	if err != nil {
		errorf("Cannot write to file: %v", err)
	}
	fmt.Printf("wrote %d bytes\n", save)
}

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func errorf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(2)
}
