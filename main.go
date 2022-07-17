package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	inputFile  string
	outputFile string
	key        string
)

const (
	ENCRYPT = iota
	DECRYPT
)

func AESCfb(inputName string, outputName string, key []byte, mode int) {
	var cfb cipher.Stream
	var err error
	iv := make([]byte, aes.BlockSize)
	inFile, err := os.Open(inputName)
	if err != nil {
		log.Fatal("open input file failed")
	}
	defer func(inFile *os.File) { _ = inFile.Close() }(inFile)
	outFile, err := os.OpenFile(outputName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		log.Fatal("open output file failed")
	}
	defer func(outFile *os.File) { _ = outFile.Close() }(outFile)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	switch mode {
	case ENCRYPT:
		_, err = rand.Read(iv)
		if err != nil {
			log.Fatal(err)
		}
		_, err = outFile.Write(iv)
		if err != nil {
			log.Fatal(err)
		}
		cfb = cipher.NewCFBEncrypter(block, iv)
	case DECRYPT:
		_, err = io.ReadFull(inFile, iv[:])
		if err != nil {
			log.Fatal(err)
		}
		_, _ = inFile.Seek(aes.BlockSize, 0)
		cfb = cipher.NewCFBDecrypter(block, iv)
	}
	s := cipher.StreamReader{
		S: cfb,
		R: inFile,
	}
	if _, err = io.Copy(outFile, s); err != nil {
		log.Println(err)
	}
}

func shaFile(fileName string) string {
	f1, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, f1); err != nil {
		fmt.Println(err)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func checkFileSha256(files []string) {
	m := make(map[string]string)
	wg := sync.WaitGroup{}
	mu := sync.Mutex{}
	for _, f := range files {
		go func() {
			sha := shaFile(f)
			mu.Lock()
			m[f] = sha
			mu.Unlock()
			wg.Done()
		}()
		wg.Add(1)
	}
	wg.Wait()
	if len(files) != 1 {
		orig := m[files[0]]
		for _, f := range files {
			log.Printf("file sha: %s [%s]", m[f], f)
			if m[f] != orig {
				log.Fatal("not equals")
			}
		}
		log.Printf("equals")
	} else {
		log.Printf("file sha: %s", m[files[0]])
	}
}

func mustNotNull(s string, name string) {
	if s == "" {
		log.Fatalf("%s is null", name)
	}
}

func init() {
	flag.StringVar(&inputFile, "i", "", "input file name")
	flag.StringVar(&outputFile, "o", "", "output file name")
	flag.StringVar(&key, "k", "", "aes key")
}

func main() {
	flag.Parse()
	keySha := sha256.Sum256([]byte(key))
	//fmt.Printf("%x", keySha)
	cmds := flag.Args()
	if len(cmds) < 1 {
		log.Fatal("no commands")
	}
	switch cmds[0] {
	case "sha":
		if len(cmds) >= 1 {
			checkFileSha256(cmds[1:])
		}
	case "e":
		mustNotNull(inputFile, "input file")
		if len(key) < 16 {
			log.Fatal("key is too short")
		}
		if outputFile == "" {
			outputFile = inputFile + ".enc"
		}
		log.Printf("encrypting %s -> %s", inputFile, outputFile)
		AESCfb(inputFile, outputFile, keySha[:], ENCRYPT)
	case "d":
		mustNotNull(inputFile, "input file")
		if outputFile == "" && strings.HasSuffix(inputFile, ".enc") {
			outputFile = inputFile[:len(inputFile)-4]
		}
		if outputFile == "" {
			outputFile = strconv.FormatInt(time.Now().Unix(), 10)
		}
		log.Printf("decrypting %s -> %s", inputFile, outputFile)
		AESCfb(inputFile, outputFile, keySha[:], DECRYPT)
	}
}
