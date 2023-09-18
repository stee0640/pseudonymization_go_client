package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/stee0640/pseudonymization_go/pseudonymizer"
	"github.com/stee0640/pseudonymization_go/salts_repo"
	"github.com/stee0640/pseudonymization_go/storage_password"
)

func readSource(fileName string) []string {
	sourceFile, err := os.Open(fileName)
	if err != nil {
		fmt.Println(err)
	}
	defer sourceFile.Close()

	var lines []string
	scanner := bufio.NewScanner(sourceFile)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

func main() {
	source := readSource(("./input/source.txt"))
	salts := salts_repo.ReadSaltRepo("./input/salts.json")

	storage_key_salt, _ := hex.DecodeString(salts.StorageKeySalt)

	storage_key := storage_password.New(storage_key_salt, nil).DeriveKey([]byte("KrypTerinG"))

	for _, salt := range salts.Salts {
		fmt.Println(salt.ShorthandName)
		p := pseudonymizer.DefaultPseudonymizer(storage_key, salt.EncryptedSalt)
		for _, cpr := range source {
			pseudonym := p.Pseudonymize(cpr)
			fmt.Println(hex.EncodeToString(pseudonym))

		}
	}
}
