package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

type AESInfo struct {
	key []byte
	iv  []byte
}

// TODO: Possibly need to read these values from the decryption tool itself as they may change from sample to sample (need to confirm this)
var EncryptedHeaderSize int64 = 0x200
var AESKeySize int64 = 0x20
var AESIVSize int64 = 0x10

func getDecryptLogic(fileSize uint64, config RansomEXXDecryptConfig) *DecryptLogic {
	for _, logic := range config.DecryptLogicList {
		if fileSize >= logic.LowerLimit && fileSize <= logic.UpperLimit {
			return &logic
		}
	}
	return nil
}

func getEncryptedHeader(file *os.File, fileSize int64, config RansomEXXDecryptConfig) ([]byte, error) {
	file.Seek(fileSize-EncryptedHeaderSize, io.SeekStart)

	header := make([]byte, EncryptedHeaderSize)
	n, err := file.Read(header)
	if err != nil {
		log.Fatalf("Failed to read from encrypted file: %s\n", err)
	}

	log.Debugf("Read 0x%x bytes from the end of the file\n", n)
	log.Debugf("\n%s\n", hex.Dump(header))

	return header, nil
}

func getAESKeyFromEncryptedHeader(header []byte, key *rsa.PrivateKey) (*AESInfo, error) {
	rnd := rand.Reader
	opts := rsa.PKCS1v15DecryptOptions{
		SessionKeyLen: 0x30,
	}
	decryptedData, err := key.Decrypt(rnd, header, &opts)
	if err != nil {
		log.Errorln("Failed to decrypt the AES key")
		log.Fatalln(err)
	}

	log.Debugf("Decrypted Key & IV:\n%s\n", hex.Dump(decryptedData))

	aesInfo := AESInfo{
		key: decryptedData[:AESKeySize],
		iv:  decryptedData[AESKeySize : AESKeySize+AESIVSize],
	}

	return &aesInfo, nil
}

// Returns the original file name given an encrypted file path
func getOriginalFilename(filepath string, config RansomEXXDecryptConfig) string {
	s := strings.Split(filepath, config.EncryptedFileExtension)
	return s[0]
}

func decryptOneFile(filepath string, config RansomEXXDecryptConfig) error {
	log.Printf("Attempting to decrypt %s\n", filepath)
	encryptedFile, err := os.OpenFile(filepath, os.O_RDWR, 0644)
	if err != nil {
		log.Errorln(err)
		return err
	}

	encryptedFileInfo, err := encryptedFile.Stat()
	if err != nil {
		log.Errorln(err)
		return err
	}
	var originalDataSize uint64 = uint64(encryptedFileInfo.Size() - EncryptedHeaderSize)
	log.Debugf("Original data size: 0x%x\n", originalDataSize)

	header, err := getEncryptedHeader(encryptedFile, encryptedFileInfo.Size(), config)
	if err != nil {
		log.Errorln(err)
		return err
	}

	key := rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: config.RSAPublicMod,
			E: int(config.RSAPublicExponent.Int64()),
		},
		D: config.RSAPrivateExponent,
		Primes: []*big.Int{
			config.RSAFirstPrimeFactor,
			config.RSASecondPrimeFactor,
		},
	}

	aesInfo, err := getAESKeyFromEncryptedHeader(header, &key)
	if err != nil {
		log.Errorln(err)
		return err
	}

	// Get original file name and create file to place decrypted contents in
	originalFilePath := getOriginalFilename(filepath, config)
	log.Debugln("Original filename: " + originalFilePath)

	decryptLogic := getDecryptLogic(originalDataSize, config)

	log.Debugf("lowerLimit: 0x%x\n", decryptLogic.LowerLimit)
	log.Debugf("upperLimit: 0x%x\n", decryptLogic.UpperLimit)
	log.Debugf("chunkSize: 0x%x\n", decryptLogic.ChunkSize)
	log.Debugf("blockSize: 0x%x\n", decryptLogic.BlockSize)

	// Calculate block count
	var blockCount uint64
	if originalDataSize < decryptLogic.BlockSize {
		blockCount = 1
	} else {
		blockCount = originalDataSize / decryptLogic.BlockSize
	}
	log.Debugln("Block count: ", blockCount)

	// Calculate the min chunk size
	var minChunkSize uint64 = 0xffffffff
	for _, logic := range config.DecryptLogicList {
		if minChunkSize > logic.ChunkSize {
			minChunkSize = logic.ChunkSize
		}
	}

	ciph, err := aes.NewCipher(aesInfo.key)
	if err != nil {
		log.Errorf("Failed to create AES cipher with the key: %s\n", err)
		return err
	}

	err = encryptedFile.Truncate(int64(originalDataSize))
	if err != nil {
		log.Errorf("Failed to truncate file %s: %s\n", filepath, err)
		return err
	}

	readSize := decryptLogic.ChunkSize
	encryptedFile.Seek(0, io.SeekStart)

	cbc := cipher.NewCBCDecrypter(ciph, aesInfo.iv)

	var i uint64
	for i = 0; i < blockCount; i++ {
		if blockCount == 1 && i == 0 && originalDataSize < minChunkSize {
			readSize = (originalDataSize - (originalDataSize+(originalDataSize>>0x5f)>>0x1c)&0xf) - ((originalDataSize >> 0x3f) >> 0x3c)
		}

		ciphertext := make([]byte, readSize&0xffffffff)
		n, err := encryptedFile.Read(ciphertext)
		if err != nil {
			log.Errorf("Failed to read block from encrypted file: %s\n", err)
			return err
		}

		cbc.CryptBlocks(ciphertext, ciphertext)

		encryptedFile.Seek(int64(-n), io.SeekCurrent)
		_, err = encryptedFile.Write(ciphertext)
		if err != nil {
			log.Errorln("Failed to write decrypted data to file, file may have been corrupted.", err)
			return err
		}

		encryptedFile.Seek(int64(decryptLogic.BlockSize), io.SeekCurrent)
	}

	// Rename file back to it's original state
	encryptedFile.Close()
	err = os.Rename(filepath, originalFilePath)
	if err != nil {
		log.Errorln("Failed to rename %s to %s\n%s\n", filepath, originalFilePath, err)
		return err
	}

	return nil
}

func decryptWorker(
	fileChannel chan string,
	errorChannel chan string,
	config RansomEXXDecryptConfig,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	for file := range fileChannel {
		err := decryptOneFile(file, config)
		if err != nil {
			log.Errorf("Failed to decrypt %s\n", file)
			errorChannel <- file
		}
	}
}

func errorCollectionWorker(errorChannel chan string, errorWg *sync.WaitGroup, failedFiles *[]string) {
	defer errorWg.Done()
	for file := range errorChannel {
		*failedFiles = append(*failedFiles, file)
	}
}

func decryptDirs(dirs []string, configFile string, numWorkers int) error {
	configFileData, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatalln(err)
	}

	var config RansomEXXDecryptConfig
	err = json.Unmarshal(configFileData, &config)
	if err != nil {
		log.Fatalln(err)
	}

	fileChannel := make(chan string)
	errorChannel := make(chan string, 1024)

	// Set up collector worker to store files which failed to decrypt
	var failedFiles []string
	var errorWg sync.WaitGroup
	errorWg.Add(1)
	go errorCollectionWorker(errorChannel, &errorWg, &failedFiles)

	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go decryptWorker(fileChannel, errorChannel, config, &wg)
	}

	for _, dir := range dirs {
		log.Printf("Scanning %s\n", dir)
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if strings.Contains(path, config.EncryptedFileExtension) {
				fileChannel <- path
			}
			return nil
		})
		if err != nil {
			log.Fatalln(err)
		}
	}

	close(fileChannel)
	wg.Wait()
	close(errorChannel)
	errorWg.Wait()

	if len(failedFiles) > 0 {
		return errors.New("Failed to decrypt some files")
	} else {
		return nil
	}
}
