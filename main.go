// Brando
// Without consulting any of the numerous public-domain implementations available,
// implement AES, on your own, from the spec or from the description provided by this chapter. Then
// test your implementation according to the test vectors provided in the AES documentation.
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf

package main

import (
	"fmt"
)

const bitLength uint = 128
const boxByteSize uint = bitLength / 8
const messageLength uint = boxByteSize
const blockByteSize uint = boxByteSize / 4
const shiftTheRows uint = 0
const shiftTheColumns uint = 1

var sBox = [boxByteSize][boxByteSize]byte{
	{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
	{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
	{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
	{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
	{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
	{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
	{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
	{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
	{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
	{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
	{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
	{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
	{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
	{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
	{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
	{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}}

var maxRounds uint = 10

// var sBoxFilename string = "./sbox.csv"
// var sBox [][]string = getCsvContent(sBoxFilename)

func main() {
	var message string = "BrandonMFongName"
	var byteMessage = []byte(message)
	var key string = "asdfghjkqwertyui"
	var byteKey = []byte(key)

	fmt.Println("Message:\t", byteMessage)
	fmt.Println("Key:\t", byteKey)

	byteMessage = AES(byteMessage, byteKey)
}

// func getCsvContent(filename string) [][]string {
// 	recordFile, err := os.Open(sBoxFilename)
// 	if err != nil {
// 		fmt.Println("An error encountered ::", err)
// 	}
// 	reader := csv.NewReader(recordFile)
// 	result, _ := reader.ReadAll()
// 	return result
// }

// AES is a function
func AES(message []byte, key []byte) []byte {
	var okayToContinue bool = true
	var state [blockByteSize][blockByteSize]byte // the 's'
	var result []byte
	// var originalKey []byte
	// var keys []byte
	var round uint

	fmt.Println("\n** WARNING: The blocks are printed left to right, then top to bottom **\n ")

	if okayToContinue {
		if len(message) != int(messageLength) {
			fmt.Println("Message must be 16 bytes long, no more, no less. ")
			okayToContinue = false
		}
	}

	if okayToContinue {
		if len(key) != int(messageLength) {
			fmt.Println("Key must be 16 bytes long, no more, no less. ")
			okayToContinue = false
		}
	}

	// Want to make sure that this message is 16 bytes long,
	// else just return the orignal message
	if okayToContinue {
		// Expand
		// keys = expand(originalKey)

		// S
		state = array2block(message)
		fmt.Println("Block:")
		printBlock(state)

		round = 0
		for round < maxRounds {
			fmt.Println("\nROUND", round)
			// S Map
			sMap(&state)
			// fmt.Println("S map:", state)
			fmt.Println("S map:")
			printBlock(state)

			// Shift rows
			shiftRows(&state)
			// fmt.Println("Shift rows:", state)
			fmt.Println("Shift rows:")
			printBlock(state)

			// mix columns
			shiftColumns(&state)
			// fmt.Println("Shift columns:", state)
			fmt.Println("Shift columns:")
			printBlock(state)

			round++
			// break
		}
	}

	// Revert the block back into an array
	result = block2array(state)

	return result
}

func expand(inputString []byte) []byte {
	var result []byte

	result = inputString

	return result
}

func sMap(block *[blockByteSize][blockByteSize]byte) {
	var tempByte byte
	var xCoor uint
	var yCoor uint

	xCoor = 0
	yCoor = 0
	for rowIndex, row := range block {
		for columnIndex, blockByte := range row {
			// fmt.Printf("%x: ", blockByte)

			// Left most 8 bits
			tempByte = blockByte & 0xF0
			tempByte = tempByte >> 4
			// fmt.Printf("%x & ", tempByte)

			// Get the x coordinate (the left most)
			xCoor = uint(tempByte)

			// Right most 8 bits
			tempByte = blockByte & 0x0F
			// fmt.Printf("%x", tempByte)

			// Get the y coordinate (the right most)
			yCoor = uint(tempByte)

			tempByte = sBox[int(xCoor)][int(yCoor)]

			// fmt.Printf(" => %x", tempByte)
			// fmt.Println()

			block[rowIndex][columnIndex] = tempByte
		}
	}
}

func array2block(array []byte) [blockByteSize][blockByteSize]byte {
	var result [blockByteSize][blockByteSize]byte
	var rowIndex uint
	var columnIndex uint

	rowIndex = 0
	columnIndex = 0
	for _, value := range array {
		result[int(rowIndex)][int(columnIndex)] = value

		// increment column
		if columnIndex >= (blockByteSize - 1) {
			columnIndex = 0

			// increment row index
			if rowIndex >= (blockByteSize - 1) {
				rowIndex = 0
			} else {
				rowIndex++
			}
		} else {
			columnIndex++
		}
	}

	return result
}

func block2array(block [blockByteSize][blockByteSize]byte) []byte {
	var result []byte
	var index uint

	index = 0
	for _, row := range block {
		for _, cell := range row {
			result = append(result, cell)
			index++
		}
	}

	return result
}

func transpose(block *[blockByteSize][blockByteSize]byte) {
	var tempBlock [blockByteSize][blockByteSize]byte

	for rowIndex, row := range block {
		for columnIndex, cell := range row {
			tempBlock[columnIndex][rowIndex] = cell
		}
	}
	*block = tempBlock
}

func shiftRows(block *[blockByteSize][blockByteSize]byte) {
	shiftBlock(shiftTheRows, block)
}

func shiftColumns(block *[blockByteSize][blockByteSize]byte) {
	shiftBlock(shiftTheColumns, block)
}

func shiftBlock(typeShift uint, block *[blockByteSize][blockByteSize]byte) {
	if typeShift == shiftTheRows {
		transpose(block)
	}

	for index, row := range *block {
		if index != 0 {
			block[index][0] = row[(0+index)%4]
			block[index][1] = row[(1+index)%4]
			block[index][2] = row[(2+index)%4]
			block[index][3] = row[(3+index)%4]
		}
	}

	// reverse the transpose
	if typeShift == shiftTheRows {
		transpose(block)
	}
}

func printBlock(block [blockByteSize][blockByteSize]byte) {
	for _, row := range block {
		fmt.Println(row)
	}
}
