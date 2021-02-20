// Brando
// Without consulting any of the numerous public-domain implementations available,
// implement AES, on your own, from the spec or from the description provided by this chapter. Then
// test your implementation according to the test vectors provided in the AES documentation.

package main

import (
	"encoding/hex"
	"fmt"
)

func main() {
	a := "73616d706c65"
	bs, err := hex.DecodeString(a)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(bs))
}
