// Brando
// Without consulting any of the numerous public-domain implementations available,
// implement AES, on your own, from the spec or from the description provided by this chapter. Then
// test your implementation according to the test vectors provided in the AES documentation.
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf

package main

import (
	"encoding/csv"
	"fmt"
	"os"
)

const bitLength uint = 128
const blockByteSize uint = bitLength / 8

var rounds uint = 10
var sBoxFilename string = "./sbox.csv"
var sBox [][]string = getCsvContent(sBoxFilename)

func main() {
	var message string = "BrandonMFongName"
	byteMessage := []byte(message)

	fmt.Println(len(byteMessage))

	message = AES(byteMessage)
}

func getCsvContent(filename string) [][]string {
	recordFile, err := os.Open(sBoxFilename)
	if err != nil {
		fmt.Println("An error encountered ::", err)
	}
	reader := csv.NewReader(recordFile)
	result, _ := reader.ReadAll()
	return result
}

// AES is a function
func AES(message []byte) []byte {
	var result []byte // the 's'
	var originalKey byte
	var keys []byte
	var index uint

	if len(message) == int(blockByteSize) {
		// Expand
		keys = expand(originalKey)

		// S
		result = message

		index = 0
		for index < rounds {
			// Shift rows

			// mix columns

			index++
		}
	}

	return result
}

func expand(inputString byte) []byte {
	var result []byte

	return result
}
