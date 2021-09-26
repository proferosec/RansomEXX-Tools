package main

import (
	"debug/elf"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/knightsc/gapstone"
	log "github.com/sirupsen/logrus"
)

// Index positions for decrypt tool configuration
const (
	DecryptConfigRSAPublicMod           = 0
	DecryptConfigRSAPublicExponent      = 1
	DecryptConfigRSAPrivateExponent     = 2
	DecryptConfigRSAFirstPrimeFactor    = 3
	DecryptConfigRSASecondPrimeFactor   = 4
	DecryptConfigRSADP                  = 5
	DecryptConfigRSADQ                  = 6
	DecryptConfigRSAQP                  = 7
	DecryptConfigEncryptedFileExtension = 8
	DecryptConfigRansomNoteFilename     = 9
)

// This is the number of possible decrypt logics (block and chunk sizes for different sized files)
var NumDecryptLogics int = 6

type RansomEXXDecryptConfigItem struct {
	itemIndex uint32
	data      []byte
}

func printSections(elfFile *elf.File) {
	for _, sec := range elfFile.Sections {
		log.Debugf("0x%x\t%s\n", sec.Addr, sec.Name)
	}
}

// Returns the read value and the new cursor value (after incrementing)
func readUint32(elfFile *elf.File, raw []byte, cursor uint64) (value uint32, newCursor uint64) {
	log.Debugf("Attempting to read uint32 from data offset: 0x%x\n", cursor)
	value = elfFile.ByteOrder.Uint32(raw[cursor : cursor+4])
	newCursor = cursor + 4
	return
}

func readUint64(elfFile *elf.File, raw []byte, cursor uint64) (value uint64, newCursor uint64) {
	log.Debugf("Attempting to read uint64 from data offset: 0x%x\n", cursor)
	value = elfFile.ByteOrder.Uint64(raw[cursor : cursor+8])
	newCursor = cursor + 8
	return
}

func readConfigItem(elfFile *elf.File, raw []byte, cursor uint64) (value RansomEXXDecryptConfigItem, newCursor uint64) {
	log.Debugf("Attempting to read RansomEXXDecryptConfigItem from data offset: 0x%x\n", cursor)
	value = RansomEXXDecryptConfigItem{}
	value.itemIndex, newCursor = readUint32(elfFile, raw, cursor)
	length, newCursor := readUint32(elfFile, raw, newCursor)

	value.data = raw[newCursor : newCursor+uint64(length-1)]

	newCursor += uint64(length)
	return
}

func parseConfig(elfFile *elf.File, raw []byte, configBufferOffset uint64) RansomEXXDecryptConfig {
	configBufferLength, newCursor := readUint32(elfFile, raw, configBufferOffset)

	// Calculate end of config buffer
	end := configBufferOffset + uint64(configBufferLength)

	numConfigItems, newCursor := readUint32(elfFile, raw, newCursor)
	log.Debugf("Number of config items: 0x%x\n", numConfigItems)
	log.Debugf("Config buffer length: 0x%x\n", configBufferLength)

	var config RansomEXXDecryptConfig

	for i := 0; i < int(numConfigItems); i++ {
		if newCursor > end {
			log.Fatalln("Cursor has seeked beyond config buffer size, config buffer may be corrupted or of an unknown format.")
		}
		var item RansomEXXDecryptConfigItem
		item, newCursor = readConfigItem(elfFile, raw, newCursor)
		log.Debugf("Found item at 0x%x with index %d\n", newCursor, item.itemIndex)

		log.Debugf("Config item value:\n%s\n", hex.Dump(item.data))

		var ok bool

		switch item.itemIndex {
		case DecryptConfigRSAPublicMod:
			config.RSAPublicMod, ok = new(big.Int).SetString(string(item.data), 16)
			if !ok {
				log.Fatalf("Failed to convert config item with index %d into a bigint\n", item.itemIndex)
			}
		case DecryptConfigRSAPublicExponent:
			config.RSAPublicExponent, ok = new(big.Int).SetString(string(item.data), 16)
			if !ok {
				log.Fatalf("Failed to convert config item with index %d into a bigint\n", item.itemIndex)
			}
		case DecryptConfigRSAPrivateExponent:
			config.RSAPrivateExponent, ok = new(big.Int).SetString(string(item.data), 16)
			if !ok {
				log.Fatalf("Failed to convert config item with index %d into a bigint\n", item.itemIndex)
			}
		case DecryptConfigRSAFirstPrimeFactor:
			config.RSAFirstPrimeFactor, ok = new(big.Int).SetString(string(item.data), 16)
			if !ok {
				log.Fatalf("Failed to convert config item with index %d into a bigint\n", item.itemIndex)
			}
		case DecryptConfigRSASecondPrimeFactor:
			config.RSASecondPrimeFactor, ok = new(big.Int).SetString(string(item.data), 16)
			if !ok {
				log.Fatalf("Failed to convert config item with index %d into a bigint\n", item.itemIndex)
			}
		case DecryptConfigRSADP:
			config.RSADP, ok = new(big.Int).SetString(string(item.data), 16)
			if !ok {
				log.Fatalf("Failed to convert config item with index %d into a bigint\n", item.itemIndex)
			}
		case DecryptConfigRSADQ:
			config.RSADQ, ok = new(big.Int).SetString(string(item.data), 16)
			if !ok {
				log.Fatalf("Failed to convert config item with index %d into a bigint\n", item.itemIndex)
			}
		case DecryptConfigRSAQP:
			config.RSAQP, ok = new(big.Int).SetString(string(item.data), 16)
			if !ok {
				log.Fatalf("Failed to convert config item with index %d into a bigint\n", item.itemIndex)
			}
		case DecryptConfigEncryptedFileExtension:
			config.EncryptedFileExtension = string(item.data)
		case DecryptConfigRansomNoteFilename:
			config.RansomNoteFilename = string(item.data)
		}
	}

	return config
}

func parseLogic(elfFile *elf.File, raw []byte, decryptLogicOffset uint64) []DecryptLogic {
	cursor := decryptLogicOffset
	var ret []DecryptLogic
	for i := 0; i < NumDecryptLogics; i++ {
		var logic DecryptLogic

		logic.LowerLimit, cursor = readUint64(elfFile, raw, cursor)
		logic.UpperLimit, cursor = readUint64(elfFile, raw, cursor)
		logic.ChunkSize, cursor = readUint64(elfFile, raw, cursor)
		logic.BlockSize, cursor = readUint64(elfFile, raw, cursor)

		ret = append(ret, logic)
	}
	return ret
}

func extractConfig(decryptToolPath string, conf Config) RansomEXXDecryptConfig {
	elfFile, err := elf.Open(decryptToolPath)
	if err != nil {
		log.Fatalln(err)
	}

	// Check binary is supported
	if elfFile.Machine.String() != "EM_X86_64" {
		log.Fatalf("%s is an unsupported architecture\n", elfFile.Machine.String())
	}

	printSections(elfFile)

	text := elfFile.Section(".text")
	if text == nil {
		log.Fatalln("Failed to find .text section")
	}

	data := elfFile.Section(".data")
	if data == nil {
		log.Fatalln("Failed to find .data section")
	}

	// Get .text section data
	textData, err := text.Data()
	if err != nil {
		log.Fatalln(err)
	}

	configLoadFromBufferOffset, err := FindWithSignature(textData, ConfigLoadFromBufferSignature)
	if err != nil {
		log.Fatalln("Failed to find ConfigLoadFromBuffer in the binary.", err)
	}

	mainOffset, err := FindWithSignature(textData, MainSignature)
	if err != nil {
		log.Fatalln("Failed to find main in the binary.", err)
	}

	getLogicByDataSizeOffset, err := FindWithSignature(textData, GetLogicByDataSizeSignature)
	if err != nil {
		log.Fatalln("Failed to find main in the binary.", err)
	}

	log.Debugf("Found ConfigLoadFromBuffer at 0x%x\n", configLoadFromBufferOffset)
	log.Debugf("Found main at 0x%x\n", mainOffset)
	log.Debugf("Found GetLogicByDataSize at 0x%x\n", getLogicByDataSizeOffset)

	// Get .data section data
	dataData, err := data.Data()
	if err != nil {
		log.Fatalln(err)
	}

	// Disassemble
	engine, err := gapstone.New(
		// TODO: Support more archs
		gapstone.CS_ARCH_X86,
		gapstone.CS_MODE_64,
	)
	if err != nil {
		log.Fatalln("Failed to open gapstone")
	}

	defer engine.Close()

	instructions, err := engine.Disasm(
		textData, // code buffer
		text.Addr,
		conf.MaxInstructionsToDisassemble, // instructions to disassemble, 0 for all
	)
	if err != nil {
		log.Fatalf("Disassembly error: %v", err)
	}

	// Find the call to ConfigLoadFromBuffer in main
	configBufferDataOffset := findDataOffsetToConfigBuffer(text.Addr, data.Addr, instructions, configLoadFromBufferOffset, mainOffset)
	log.Debugf("Found config at .data+0x%x:\n%s\n", configBufferDataOffset, hex.Dump(dataData[configBufferDataOffset:configBufferDataOffset+1024]))

	// Find pointer to the decrypt logic buffer using the first lea instruction in GetLogicByDataSize
	decryptLogicDataOffset := findDataOffsetToLogicBuffer(text.Addr, data.Addr, instructions, getLogicByDataSizeOffset)
	log.Debugf("Found decrypt logic at .data+0x%x:\n%s\n", decryptLogicDataOffset, hex.Dump(dataData[decryptLogicDataOffset:decryptLogicDataOffset+128]))

	config := parseConfig(elfFile, dataData, configBufferDataOffset)
	config.DecryptLogicList = parseLogic(elfFile, dataData, decryptLogicDataOffset)

	log.Println(config.DecryptLogicList)

	return config
}

func findDataOffsetToConfigBuffer(
	textAddr uint64,
	dataAddr uint64,
	instructions []gapstone.Instruction,
	configLoadFromBufferOffset uint64,
	mainOffset uint64,
) uint64 {
	mainIndex := 0
	callIndex := 0
	for i, ins := range instructions {
		if uint64(ins.Address) == textAddr+mainOffset {
			mainIndex = i
		}

		if mainIndex != 0 {
			log.Debugf("0x%x:\t%s\t\t%s\n", ins.Address, ins.Mnemonic, ins.OpStr)
		}

		var configLoadFromBufferOpStr string
		configLoadFromBufferOpStr = fmt.Sprintf("0x%x", textAddr+configLoadFromBufferOffset)

		if mainIndex != 0 && ins.Mnemonic == "call" && ins.OpStr == configLoadFromBufferOpStr {
			log.Debugf("Found call to ConfigLoadFromBuffer in main at 0x%x.\n", ins.Address)
			callIndex = i
			break
		}
	}

	// Find pointer to the config buffer
	var configBufferOffset uint64
	var leaIns gapstone.Instruction

	log.Debugln("Working backwards to get the pointer to the config buffer")
	for i := callIndex; i > -1; i-- {
		ins := instructions[i]
		log.Debugf("0x%x: %s\t%s\n", ins.Address, ins.Mnemonic, ins.OpStr)
		if ins.Mnemonic == "lea" && ins.OpStr[:3] == "rax" {
			leaIns = ins
			log.Debugf("Found the write to rax at 0x%x\n", ins.Address)
			fmt.Fscanf(strings.NewReader(ins.OpStr[12:len(ins.OpStr)-1]), "0x%x", &configBufferOffset)
			break
		}
	}
	if configBufferOffset == 0 {
		log.Fatalln("Failed to find pointer to the config buffer")
	}

	log.Debugf("Config buffer pointer: 0x%x\n", configBufferOffset)
	ripValue := leaIns.Address + leaIns.Size
	log.Debugf("ripValue: 0x%x\n", ripValue)

	return uint64(ripValue) + configBufferOffset - dataAddr
}

func findDataOffsetToLogicBuffer(
	textAddr uint64,
	dataAddr uint64,
	instructions []gapstone.Instruction,
	getLogicByDataSizeOffset uint64,
) uint64 {
	var leaIns gapstone.Instruction
	var decryptLogicBufferOffset uint64

	GetLogicByDataSizeIndex := 0
	for i, ins := range instructions {
		if uint64(ins.Address) == textAddr+getLogicByDataSizeOffset {
			GetLogicByDataSizeIndex = i
		}

		if GetLogicByDataSizeIndex != 0 {
			log.Debugf("0x%x:\t%s\t\t%s\n", ins.Address, ins.Mnemonic, ins.OpStr)
		}

		if GetLogicByDataSizeIndex != 0 && ins.Mnemonic == "lea" {
			leaIns = ins
			log.Debugf("Found first lea in GetLogicByDataSize at 0x%x.\n", ins.Address)
			fmt.Fscanf(strings.NewReader(ins.OpStr[12:len(ins.OpStr)-1]), "0x%x", &decryptLogicBufferOffset)
			break
		}
	}
	if decryptLogicBufferOffset == 0 {
		log.Fatalln("Failed to find pointer to the decrypt logic buffer")
	}

	ripValue := leaIns.Address + leaIns.Size
	log.Debugf("ripValue: 0x%x\n", ripValue)
	log.Debugf("decryptLogicBufferOffset: 0x%x\n", decryptLogicBufferOffset)

	return uint64(ripValue) + decryptLogicBufferOffset - dataAddr
}
