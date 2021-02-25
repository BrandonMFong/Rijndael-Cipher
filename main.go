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
const keyLength uint = boxByteSize
const blockByteSize uint = boxByteSize / 4
const constantLength uint = blockByteSize
const shiftTheRows uint = 0
const shiftTheColumns uint = 1
const keyArraySize uint = 11
const constantArraySize uint = 11

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

var constants = [constantArraySize][constantLength]byte{
	{0x02, 0x00, 0x00, 0x00},
	{0x04, 0x00, 0x00, 0x00},
	{0x08, 0x00, 0x00, 0x00},
	{0x10, 0x00, 0x00, 0x00},
	{0x20, 0x00, 0x00, 0x00},
	{0x40, 0x00, 0x00, 0x00},
	{0x80, 0x00, 0x00, 0x00},
	{0x1B, 0x00, 0x00, 0x00},
	{0x36, 0x00, 0x00, 0x00},
	{0x6C, 0x00, 0x00, 0x00}}

var mixColumnMatrix = [blockByteSize][blockByteSize]byte{
	{0x02, 0x03, 0x01, 0x01},
	{0x01, 0x02, 0x03, 0x01},
	{0x01, 0x02, 0x02, 0x03},
	{0x03, 0x01, 0x01, 0x02}}

var maxRounds uint = 10

// No constraints on the variables in main
func main() {
	var message string = "BrandonMFongName"
	var byteMessage = []byte(message)
	var key string = "asdfghjkqwertyui"
	var byteKey = []byte(key)
	var cipherText string

	// Validating
	// Overriding the values above for validation
	// another: http://www.herongyang.com/Cryptography/AES-Example-Vector-of-AES-Encryption.html
	// Using validation set F.1.1: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
	byteKey = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	byteMessage = []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	fmt.Println("Message:\t", byteMessage)
	// fmt.Println("Hex Message:\t", stringToHex(byteMessage))
	fmt.Println("Key:\t", byteKey)
	// fmt.Println("Hex Key:\t", stringToHex(byteKey))

	byteMessage = AES(byteMessage, byteKey)

	fmt.Println("")

	cipherText = string(byteMessage)
	fmt.Println("RESULTS:")
	fmt.Println("\tCipher Bytes:\t\t", byteMessage)
	fmt.Println("\tRaw Cipher Text:\t", cipherText)
	fmt.Println("\tBinary Cipher Text:\t", stringToBin(cipherText))
	fmt.Println("\tHex Cipher Text:\t", stringToHex(cipherText))
}

// AES is a function
func AES(message []byte, key []byte) []byte {
	var okayToContinue bool = true
	var state [blockByteSize][blockByteSize]byte // the 's'
	var result []byte
	var originalKey [keyLength]byte
	var keys [keyArraySize][keyLength]byte
	var round uint

	round = 0
	copy(originalKey[:], key[:int(keyLength)]) // Variable size to fixed size

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
		/* Expand */
		keys = expand(originalKey)
		fmt.Println("Keys:")
		printKeys(keys)

		fmt.Println("")

		/* S initialization */
		// converting array to block for calculations below
		state = array2block(message)
		xorBlockAndRoundKey(&state, keys[round])
		fmt.Println("Block:")
		printBlock(state)

		for round < maxRounds {
			fmt.Println("\nROUND", round)

			/* S Map */
			sMapForBlock(&state)
			fmt.Print("S map: ")
			printHexState(state)
			fmt.Println("")

			/* Shift rows */
			shiftRows(&state)
			fmt.Print("Shift rows: ")
			printHexState(state)
			fmt.Println("")

			/* mix columns */
			if round < (maxRounds - 1) {
				mixColumns(&state)
				fmt.Print("Shift columns: ")
				printHexState(state)
				fmt.Println("")
			}

			/* xor state with round key */
			xorBlockAndRoundKey(&state, keys[round])

			fmt.Print("Round result: ")
			printHexState(state)

			fmt.Println("")

			round++
			// break
		}
	}

	// Revert the block back into an array
	result = block2array(state)

	return result
}
func printHexState(state [blockByteSize][blockByteSize]byte) {
	for _, row := range state {
		for _, cell := range row {
			fmt.Printf("%x ", cell)
		}
	}
}

func xorBlockAndRoundKey(state *[blockByteSize][blockByteSize]byte, key [keyLength]byte) {
	var tempArray []byte
	var okayToContinue bool = true

	tempArray = block2array(*state)

	if len(tempArray) != len(key) {
		fmt.Println("Cannot xor operands")
		okayToContinue = false
	}

	if okayToContinue {

		for i, byteKey := range key {
			tempArray[i] = tempArray[i] ^ byteKey
		}

		*state = array2block(tempArray)
	}
}

// Keep an eye on your logic
// This creates the 11 keys
func expand(inputKey [keyLength]byte) [keyArraySize][keyLength]byte {
	var result [keyArraySize][keyLength]byte
	var tempBlockPrev [blockByteSize][blockByteSize]byte // for operations
	var tempBlockCurr [blockByteSize][blockByteSize]byte // to use for results
	var tempByteArray []byte
	var tempSlice [blockByteSize]byte // This is used in the first column
	var defaultSlice [blockByteSize]byte = [blockByteSize]byte{0xFF, 0xFF, 0xFF, 0xFF}
	var x [blockByteSize]byte = [blockByteSize]byte{0x00, 0x00, 0x00, 0x00}
	var y [blockByteSize]byte = [blockByteSize]byte{0x00, 0x00, 0x00, 0x00}
	var z [blockByteSize]byte = [blockByteSize]byte{0x00, 0x00, 0x00, 0x00}

	result[0] = inputKey
	for i := 1; i < int(constantArraySize); i++ {

		// NOT TRANSPOSING, SO IN ANIMATION OUR ROWS ARE THEIR COLUMNS
		// Get the previous block
		tempByteArray = result[i-1][:]
		tempBlockPrev = array2block(tempByteArray)
		tempSlice = tempBlockPrev[3] // I need this row before we transpose it
		// transpose(&tempBlockPrev)

		// Get the current block
		tempByteArray = result[i][:]
		tempBlockCurr = array2block(tempByteArray)
		// transpose(&tempBlockPrev)

		sMapForSlice(&tempSlice) // map sbox

		// shift cells for the slice
		for j := 0; j < int(blockByteSize); j++ {
			tempSlice[j] = tempBlockPrev[3][(j+1)%4]
		}

		// Recall you transposed the blocks
		// So you are sweeping the columns
		// Constants are sweeping the rows
		for j := 0; j < int(blockByteSize); j++ {
			x = tempBlockPrev[j]
			if j > 1 {
				y = tempBlockCurr[j-1]
				z = defaultSlice
			} else {
				y = tempSlice
				z = constants[i]
			}

			tempBlockCurr[j] = xorSlices(x, y, z)
		}

		tempByteArray = block2array(tempBlockCurr)
		copy(result[i][:], tempByteArray[:int(keyLength)])
	}

	return result
}

// Will not rely on transpose.  I don't think I need to transpose above
func xorSlices(x [constantLength]byte, y [constantLength]byte, z [constantLength]byte) [constantLength]byte {
	var result [constantLength]byte

	for i := 0; i < int(constantLength); i++ {
		result[i] = x[i] ^ y[i] ^ z[i]
	}
	return result
}

func sMapForSlice(slice *[blockByteSize]byte) {
	var tempByte byte
	var xCoor uint
	var yCoor uint

	xCoor = 0
	yCoor = 0
	for index, sliceByte := range slice {
		// fmt.Printf("%x: ", blockByte)

		/* Calculating the x coordinate for sbox */
		// Left most 8 bits
		tempByte = sliceByte & 0xF0
		tempByte = tempByte >> 4
		// fmt.Printf("%x & ", tempByte)

		// Get the x coordinate (the left most)
		xCoor = uint(tempByte)

		/* Calculating the x coordinate for sbox */
		// Right most 8 bits
		tempByte = sliceByte & 0x0F
		// fmt.Printf("%x", tempByte)

		// Get the y coordinate (the right most)
		yCoor = uint(tempByte)

		tempByte = sBox[int(xCoor)][int(yCoor)]

		// fmt.Printf(" => %x", tempByte)
		// fmt.Println()

		slice[index] = tempByte
	}
}

func sMapForBlock(block *[blockByteSize][blockByteSize]byte) {
	var tempByte byte
	var xCoor uint
	var yCoor uint

	xCoor = 0
	yCoor = 0
	for rowIndex, row := range block {
		for columnIndex, blockByte := range row {
			// fmt.Printf("%x: ", blockByte)

			// Left most 4 bits
			tempByte = blockByte & 0xF0
			tempByte = tempByte >> 4
			// fmt.Printf("%x & ", tempByte)

			// Get the x coordinate (the left most)
			xCoor = uint(tempByte)

			// Right most 4 bits
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

func mixColumns(block *[blockByteSize][blockByteSize]byte) {
	// transpose(block)
	var index uint
	var indexTwo uint
	// var indexThree uint
	var size uint
	var sizeTwo uint
	// var sizeThree uint
	var a0 byte
	var a1 byte
	var a2 byte
	var a3 byte

	size = blockByteSize
	index = 0
	for index < size {

		sizeTwo = blockByteSize
		indexTwo = 0
		for indexTwo < sizeTwo {

			a0 = mixColumnMatrix[indexTwo][0] & block[index][0]
			a1 = mixColumnMatrix[indexTwo][1] & block[index][1]
			a3 = mixColumnMatrix[indexTwo][2] & block[index][2]
			a0 = mixColumnMatrix[indexTwo][3] & block[index][3]

			block[index][indexTwo] = a0 ^ a1 ^ a2 ^ a3

			indexTwo++
		}

		index++
	}

	// transpose(block)
}

func shiftBlock(typeShift uint, block *[blockByteSize][blockByteSize]byte) {
	// if typeShift == shiftTheRows {
	transpose(block)
	// }

	for index, row := range *block {
		if index != 0 {
			block[index][0] = row[(0+index)%4]
			block[index][1] = row[(1+index)%4]
			block[index][2] = row[(2+index)%4]
			block[index][3] = row[(3+index)%4]
		}
	}

	// reverse the transpose
	// if typeShift == shiftTheRows {
	transpose(block)
	// }
}

func printBlock(block [blockByteSize][blockByteSize]byte) {
	for _, row := range block {
		fmt.Println(row)
	}
}

func printKeys(keys [keyArraySize][keyLength]byte) {
	for _, row := range keys {
		fmt.Println(row)
	}
}

func stringToBin(s string) (binString string) {
	for _, c := range s {
		binString = fmt.Sprintf("%s%b", binString, c)
	}
	return
}

func stringToHex(s string) (hexString string) {
	for _, c := range s {
		hexString = fmt.Sprintf("%s%x", hexString, c)
	}
	return
}
