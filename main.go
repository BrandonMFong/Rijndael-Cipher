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

	fmt.Println("Message: ", byteMessage)

	byteMessage = AES(byteMessage)
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
	var state []byte // the 's'
	var result []byte
	// var originalKey []byte
	// var keys []byte
	var index uint

	// Want to make sure that this message is 16 bytes long,
	// else just return the orignal message
	if len(message) == int(blockByteSize) {
		// Expand
		// keys = expand(originalKey)

		// S
		state = message

		index = 0
		for index < rounds {
			// S Map
			state = sMap(state)

			// Shift rows

			// mix columns

			index++
		}
	} else {
		fmt.Println("Message must be 16 bytes long, no more, no less. ")
	}

	result = state

	return result
}

func expand(inputString []byte) []byte {
	var result []byte

	result = inputString

	return result
}

func sMap(block []byte) []byte {
	var result []byte
	var tempByte byte
	var xCoor uint
	var yCoor uint
	var sMapResult string

	xCoor = 0
	yCoor = 0
	for _, blockByte := range block {
		fmt.Printf("%x: ", blockByte)

		// Left most 8 bits
		tempByte = blockByte & 0xF0
		tempByte = tempByte >> 4
		fmt.Printf("%x & ", tempByte)

		// Get the x coordinate (the left most)
		xCoor = uint(tempByte)

		// Right most 8 bits
		tempByte = blockByte & 0x0F
		fmt.Printf("%x", tempByte)

		// Get the y coordinate (the right most)
		yCoor = uint(tempByte)

		sMapResult = sBox[int(xCoor)][int(yCoor)]

		fmt.Print(" => ", sMapResult)

		fmt.Println()
	}

	result = block

	return result
}
