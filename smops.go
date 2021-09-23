package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/wyrepo/wuyou-crypto-go/sm/sm2"
	"github.com/wyrepo/wuyou-crypto-go/sm/sm3"
	"github.com/wyrepo/wuyou-crypto-go/sm/sm4"
	"github.com/wyrepo/wuyou-crypto-go/sm/util"
	"log"
)

func main() {
	// sm2 sign and verify
	sm2Ops()
	// sm3 digest
	sm3Ops()
	// sm4 encrypt and decrypt
	sm4Ops()

}

func sm2Ops() {
	// handle at client side (in app server)
	privateKay, err := sm2.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	publicKey, _ := privateKay.Public().(*sm2.PublicKey)
	msg := []byte("123456")
	sign, err := sm2Sign(msg, privateKay)
	if err != nil {
		log.Fatal(err)
	}
	pkHex := util.WritePublicKeyToHex(publicKey)

	// send "msg, sign, pkHex" to remote side...

	// handle at server side (in chaincode)
	b, err := sm2Verify(msg, sign, pkHex)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Verify is %v\n", b)
}

func sm2Sign(msg []byte, sk *sm2.PrivateKey) ([]byte, error) {
	if msg == nil || len(msg) == 0 || sk == nil {
		return nil, errors.New("some args are nil or empty")
	}
	sign, err := sk.Sign(rand.Reader, []byte(msg), nil)
	if err != nil {
		fmt.Printf("Sign using private key error:%v\n", err)
		return nil, err
	}
	return sign, nil
}

func sm2Verify(msg, sign []byte, pkHex string) (bool, error) {
	if msg == nil || sign == nil {
		return false, errors.New("some args are nil")
	}
	if len(msg) == 0 || len(sign) == 0 || pkHex == "" {
		return false, errors.New("some args are empty")
	}
	publicKey, err := util.ReadPublicKeyFromHex(pkHex)
	if err != nil {
		return false, err
	}
	// verify
	ok := publicKey.Verify(msg, sign)
	if !ok {
		return false, errors.New("verify using public key error")
	} else {
		fmt.Printf("Verify using public key ok\n")
		return true, nil
	}
}

func sm3Ops() {
	// handle at server side (in chaincode)
	msg := []byte("123456")
	hash := sm3.Sm3Sum(msg)
	hashHex := fmt.Sprintf("%02x", hash)
	fmt.Printf("digest:%s\n", hashHex)
}

func sm4Ops() {
	// handle at client side (in app server)
	key := []byte("1234567890abcdef") // SM4 key size must be 16
	msg := []byte("123456")
	msgEncrypted, err := sm4Encrypt(key, msg)
	if err != nil {
		log.Fatalf("SM4 encrypt error:%v\n", err)
	}
	fmt.Printf("msgEncrypted:%02x\n", msgEncrypted)

	// invoke chaincode to put state
	// send "msgEncrypted" to remote side...
	//
	// invoke chaincode to get state
	// send back "msgEncrypted" from remote side...

	// handle at client side (in app server)
	msgDecrypted, err := sm4Decrypt(key, msgEncrypted)
	if err != nil {
		log.Fatalf("SM4 decrypt error:%v\n", err)
	}
	fmt.Printf("msgDecrypted:%s\n", msgDecrypted)
}

func sm4Encrypt(key, msg []byte) ([]byte, error) {
	if key == nil || msg == nil || len(key) == 0 || len(msg) == 0 {
		return nil, errors.New("some args are nil or empty")
	}
	// encrypt, mode = true
	msgEncrypted, err := sm4.Sm4Cbc(key, msg, true)
	if err != nil {
		return nil, err
	}
	return msgEncrypted, nil
}

func sm4Decrypt(key, text []byte) ([]byte, error) {
	if key == nil || text == nil || len(key) == 0 || len(text) == 0 {
		return nil, errors.New("some args are nil or empty")
	}
	// decrypt, mode = false
	msgDecrypted, err := sm4.Sm4Cbc(key, text, false)
	if err != nil {
		return nil, err
	}
	return msgDecrypted, nil
}
