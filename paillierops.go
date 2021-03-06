package main

import (
	"fmt"
	"github.com/wyrepo/wuyou-crypto-go/paillier/key"
	"github.com/wyrepo/wuyou-crypto-go/paillier/num"
	"github.com/wyrepo/wuyou-crypto-go/paillier/util"
	"io/ioutil"
	"log"
	"math"
	"math/big"
)

func main() {
	// examples for key converting
	keyConverting()

	// examples for key serialization and deserialization
	keyMarshalAndUnmarshal()
	keyWriteAndRead()

	// paillier add/sub/mul/div
	paillierOps()
}

func keyConverting() {
	publicKey, privateKey, err := key.NewKeyPair(1024, math.MaxInt64)
	if err != nil {
		log.Fatalf("New key pair error:%v\n", err)
	}
	// add using original operands
	var eX, eY *num.Int
	x := big.NewInt(100000)
	y := big.NewInt(20)
	eX = num.NewInt(publicKey, x)
	eY = num.NewInt(publicKey, y)
	sum := new(num.Int).AddCiphertext(eX, eY).Decrypt(privateKey)

	// Paillier Int to Hex String (serialize)
	eXStr, err := util.IntToHexStr(eX)
	if err != nil {
		log.Fatalf("Key (*num.Int) to Hex String error:%v\n", err)
	}
	fmt.Printf("eX HexStr:%s\n", eXStr) // 1026 characters
	eYStr, err := util.IntToHexStr(eY)
	if err != nil {
		log.Fatalf("Key (*num.Int) to Hex String error:%v\n", err)
	}
	fmt.Printf("eY HexStr:%s\n", eYStr) // 1026 characters

	// Hex string to Paillier Int (deserialize)
	eXNum, err := util.HexStrToInt(publicKey, eXStr)
	if err != nil {
		log.Fatalf("Hex string to key (*num.Int) error:%v\n", err)
	}
	eYNum, err := util.HexStrToInt(publicKey, eYStr)
	if err != nil {
		log.Fatalf("Hex string to key (*num.Int) error:%v\n", err)
	}

	// add using new operands
	sum2 := new(num.Int).AddCiphertext(eXNum, eYNum).Decrypt(privateKey)
	fmt.Printf("sum:%v, sum2:%v\n", sum, sum2)
}

func keyMarshalAndUnmarshal() {
	publicKey, privateKey, err := key.NewKeyPair(1024, math.MaxInt64)
	if err != nil {
		log.Fatalf("New key pair error:%v\n", err)
	}
	fmt.Printf("pk.len:%v\n", publicKey.Length) // 1024

	// serialize public key
	bytes, err := util.MarshalPublicKey(publicKey)
	if err != nil {
		log.Fatalf("Marshal public key error:%v\n", err)
	}
	// deserialize public key
	pk, err := util.UnmarshalPublicKey(bytes)
	if err != nil {
		log.Fatalf("Unmarshal public key error:%v\n", err)
	}
	fmt.Printf("pk.len:%v\n", pk.Length) // 1024

	// serialize private key
	bytes2, err := util.MarshalPrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Marshal private key error:%v\n", err)
	}
	// deserialize private key
	sk, err := util.UnmarshalPrivateKey(bytes2)
	if err != nil {
		log.Fatalf("Unmarshal private key error:%v\n", err)
	}
	fmt.Printf("pk.len:%v\n", sk.PublicKey.Length) // 1024
}

func keyWriteAndRead() {
	publicKey, privateKey, err := key.NewKeyPair(1024, math.MaxInt64)
	if err != nil {
		log.Fatalf("New key pair error:%v\n", err)
	}
	fmt.Printf("pk.len:%v\n", publicKey.Length) // 1024

	// write public key to pem file
	pkPem, err := util.WritePublicKeyToPem(publicKey)
	if err != nil {
		log.Fatalf("Write public key to pem error:%v\n", err)
	}
	fmt.Println(string(pkPem))
	ioutil.WriteFile("publickey.key", pkPem, 0644)
	// read public key from pem file
	pkPem, err = ioutil.ReadFile("publickey.key")
	if err != nil {
		log.Fatalf("Read public key from pem file error:%v\n", err)
	}
	pk, err := util.ReadPublicKeyFromPem(pkPem)
	if err != nil {
		log.Fatalf("Read public key from pem error:%v\n", err)
	}
	fmt.Printf("pk.len:%v\n", pk.Length) // 1024

	// write private key to pem file
	skPem, err := util.WritePrivateKeyToPem(privateKey)
	if err != nil {
		log.Fatalf("Write private key to pem error:%v\n", err)
	}
	fmt.Println(string(skPem))
	ioutil.WriteFile("privatekey.key", skPem, 0644)
	// read private key from pem file
	skPem, err = ioutil.ReadFile("privatekey.key")
	if err != nil {
		log.Fatalf("Read private key from pem file error:%v\n", err)
	}
	sk, err := util.ReadPrivateKeyFromPem(skPem)
	if err != nil {
		log.Fatalf("Read private key from pem error:%v\n", err)
	}
	fmt.Printf("pk.len:%v\n", sk.PublicKey.Length) // 1024
}

func paillierOps() {
	publicKey, privateKey, err := key.NewKeyPair(1024, math.MaxInt64)
	if err != nil {
		log.Fatalf("New key pair error:%v\n", err)
	}
	var eX, eY *num.Int
	operands := [][]int64{
		{100, -23}, // DivPlainText will overflow (must be "x mod y == 0")
		{100, -20}, {-100, 20}, {100, 20}, {-100, -20},
		{0, 20}, {0, -20},
		{100, 0}, // DivPlainText will check operand "0"
	}
	for _, operand := range operands {
		operandX := operand[0]
		operandY := operand[1]
		fmt.Printf("x:%v y:%v\n", operandX, operandY)

		x := big.NewInt(operandX)
		y := big.NewInt(operandY)

		// add ciphertext
		eX = num.NewInt(publicKey, x)
		eY = num.NewInt(publicKey, y)
		sum := new(num.Int).AddCiphertext(eX, eY).Decrypt(privateKey)
		fmt.Printf("add ciphertext:%v\n", sum)

		// sub ciphertext
		eX = num.NewInt(publicKey, x)
		eY = num.NewInt(publicKey, y)
		diff := new(num.Int).SubCiphertext(eX, eY).Decrypt(privateKey)
		fmt.Printf("sub ciphertext:%v\n", diff)

		// add plaintext
		eX = num.NewInt(publicKey, x)
		sum = new(num.Int).AddPlaintext(eX, y).Decrypt(privateKey)
		fmt.Printf("add plaintext:%v\n", sum)

		// mul plaintext
		eX = num.NewInt(publicKey, x)
		prod := new(num.Int).MulPlaintext(eX, y).Decrypt(privateKey)
		fmt.Printf("mul plaintext:%v\n", prod)

		// div plaintext
		eX = num.NewInt(publicKey, x)
		quotient := new(num.Int).DivPlaintext(eX, y).Decrypt(privateKey) // must be "x mod y == 0", avoid overflowing
		fmt.Printf("div plaintext:%v\n", quotient)
		fmt.Println("-----------------------------")
	}

}
