// Brando
// Without consulting any of the numerous public-domain implementations available,
// implement AES, on your own, from the spec or from the description provided by this chapter. Then
// test your implementation according to the test vectors provided in the AES documentation.

package main

import "fmt"

func main() {
	message := "Hello"
	byteMessage := []byte(message)

	fmt.Println(byteMessage)
}
