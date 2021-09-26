package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
)

type Config struct {
	MaxInstructionsToDisassemble uint64
}

func main() {
	conf := Config{
		MaxInstructionsToDisassemble: 10000,
	}

	decryptPtr := flag.Bool("decrypt", false, "Decrypt a list of directories")
	configPtr := flag.String("config", "", "Path of the extracted config file to use for decryption")
	dirsPtr := flag.String("dirs", "", "A list of directories to recursively decrypt, separated by a comma")
	numWorkersPtr := flag.Int("num-workers", runtime.NumCPU(), "Number of workers to use for decryption")
	exconfigPtr := flag.Bool("exconfig", false, "Extract the config from a decryption tool provided by the RansomEXX group")
	decryptionToolPtr := flag.String("decryption-tool", "", "Path to the decryption tool to extract the config from. Required when using -exconfig")
	outPtr := flag.String("out", "", "The file to save the extracted config to")
	debugPtr := flag.Bool("debug", false, "Log debug output")
	flag.Parse()

	log.Debugf("decryptPtr: %t, exconfigPtr: %t\n", *decryptPtr, *exconfigPtr)

	if *exconfigPtr && *decryptPtr {
		log.Fatalln("Please use -exconfig or -decrypt, not both")
	}

	if *debugPtr {
		log.Infoln("Turning on debug messages")
		log.SetLevel(log.DebugLevel)
	}

	if *exconfigPtr {
		if *decryptionToolPtr == "" {
			log.Fatalln("Please supply the path to the decryption tool to extract config from")
		}
		if *outPtr == "" {
			log.Fatalln("Please supply the path to save the config to")
		}

		log.Printf("Extracting config from %s\n", *decryptionToolPtr)
		config := extractConfig(*decryptionToolPtr, conf)

		jsonConfig, err := json.Marshal(config)
		if err != nil {
			log.Fatalln(err)
		}

		log.Printf("Saving config to %s\n", *outPtr)
		err = ioutil.WriteFile(*outPtr, jsonConfig, 0644)
		if err != nil {
			log.Fatalln("Failed to write output file")
		}
	} else if *decryptPtr {
		if *configPtr == "" {
			log.Fatalln("Please supply the path to an extracted config file with -config")
		}

		if *dirsPtr == "" {
			log.Fatalln("Please supply a list of directories to recursively decrypt with -dirs")
		}

		dirs := strings.Split(*dirsPtr, ",")

		err := decryptDirs(dirs, *configPtr, *numWorkersPtr)
		if err != nil {
			log.Errorln("Decryption completed with errors, some files may have failed to decrypt")
		} else {
			log.Println("Decryption completed succesfully")
		}
	}
}
