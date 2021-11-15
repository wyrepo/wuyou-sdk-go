package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/wyrepo/wuyou-crypto-go/paillier/key"
	"github.com/wyrepo/wuyou-crypto-go/paillier/num"
	paillierutil "github.com/wyrepo/wuyou-crypto-go/paillier/util"
	"github.com/wyrepo/wuyou-crypto-go/sm/sm2"
	"github.com/wyrepo/wuyou-crypto-go/sm/sm3"
	"github.com/wyrepo/wuyou-crypto-go/sm/sm4"
	smutil "github.com/wyrepo/wuyou-crypto-go/sm/util"
	"github.com/wyrepo/wuyou-sdk-go/client"
	"log"
	"math"
	"math/big"
	"time"
)

const (
	configPath    = "config.yaml"
	channelName   = "mychannel"
	userName      = "User1"
	chaincodeName = "crypto"
)

func main() {
	cli := client.New(configPath, channelName, userName)
	defer cli.Close()

	// set, put, get, history
	talk(cli)

	// verify
	sm2Ops2(cli)

	// digest
	sm3Ops2(cli)

	// set, get
	sm4Ops2(cli)

	// paillier ciphertext
	paillierCiphertext2(cli)

	// paillier plaintext
	paillierPlaintext2(cli)

}

// ---------------------------- Chaincode methods ------------------------------------
func get(cli *client.Client, key string) (channel.Response, error) {
	req := channel.Request{
		ChaincodeID: chaincodeName,
		Fcn:         "get",
		Args:        [][]byte{[]byte(key)},
	}
	return cli.CC.Execute(req)
}

func put(cli *client.Client, key, value string) (channel.Response, error) {
	req := channel.Request{
		ChaincodeID: chaincodeName,
		Fcn:         "put",
		Args:        [][]byte{[]byte(key), []byte(value)},
	}
	return cli.CC.Execute(req)
}

func set(cli *client.Client, key, value string) (channel.Response, error) {
	req := channel.Request{
		ChaincodeID: chaincodeName,
		Fcn:         "set",
		Args:        [][]byte{[]byte(key), []byte(value)},
	}
	return cli.CC.Execute(req)
}

func history(cli *client.Client, key string) (channel.Response, error) {
	req := channel.Request{
		ChaincodeID: chaincodeName,
		Fcn:         "history",
		Args:        [][]byte{[]byte(key)},
	}
	return cli.CC.Execute(req)
}

func verify(cli *client.Client, key, msg, pkHex string) (channel.Response, error) {
	req := channel.Request{
		ChaincodeID: chaincodeName,
		Fcn:         "verify",
		Args:        [][]byte{[]byte(key), []byte(msg), []byte(pkHex)},
	}
	return cli.CC.Execute(req)
}

func digest(cli *client.Client, key, value string) (channel.Response, error) {
	req := channel.Request{
		ChaincodeID: chaincodeName,
		Fcn:         "digest",
		Args:        [][]byte{[]byte(key), []byte(value)},
	}
	return cli.CC.Execute(req)
}

func paillierCiphertext(cli *client.Client, key, pkHex, yHex string) (channel.Response, error) {
	req := channel.Request{
		ChaincodeID: chaincodeName,
		Fcn:         "paillierCiphertext",
		Args:        [][]byte{[]byte(key), []byte(pkHex), []byte(yHex)},
	}
	return cli.CC.Execute(req)
}

func paillierPlaintext(cli *client.Client, key, pkHex, yDec string) (channel.Response, error) {
	req := channel.Request{
		ChaincodeID: chaincodeName,
		Fcn:         "paillierPlaintext",
		Args:        [][]byte{[]byte(key), []byte(pkHex), []byte(yDec)},
	}
	return cli.CC.Execute(req)
}

func talk(cli *client.Client) {
	resp, err := set(cli, "Alice", "hello everyone")
	if err != nil {
		log.Printf("Set chaincode error: %v\n", err)
	}
	log.Printf("Set chaincode tx response:\ntx: %s\nresult: %v\n\n", resp.TransactionID, string(resp.Payload))

	time.Sleep(time.Second * 2)

	resp, err = get(cli, "Alice")
	if err != nil {
		log.Printf("Get chaincode error: %v\n", err)
	}
	log.Printf("Get chaincode tx response:\ntx: %s\nresult: %v\n\n", resp.TransactionID, string(resp.Payload))

	resp, err = put(cli, "Bob", "hello Alice")
	if err != nil {
		log.Printf("Put chaincode error: %v\n", err)
	}
	log.Printf("Put chaincode tx response:\ntx: %s\nresult: %v\n\n", resp.TransactionID, string(resp.Payload))

	time.Sleep(time.Second * 2)

	resp, err = get(cli, "Bob")
	if err != nil {
		log.Printf("Get chaincode error: %v\n", err)
	}
	log.Printf("Get chaincode tx response:\ntx: %s\nresult: %v\n\n", resp.TransactionID, string(resp.Payload))

	resp, err = history(cli, "Alice")
	if err != nil {
		log.Printf("History chaincode error: %v\n", err)
	}
	log.Printf("History chaincode tx response:\ntx: %s\nresult: %v\n\n", resp.TransactionID, string(resp.Payload))
}

// ------------------------------------ SM2/SM3/SM4 ---------------------------------------------
func sm2Ops2(cli *client.Client) {
	// handle at client side (in app server)
	privateKay, err := sm2.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	publicKey, _ := privateKay.Public().(*sm2.PublicKey)
	msg := []byte("123456")
	sign, err := sm2Sign2(msg, privateKay)
	if err != nil {
		log.Fatal(err)
	}
	pkHex := smutil.WritePublicKeyToHex(publicKey)

	// set first, send "key, sign" to remote side...
	resp, err := set(cli, "Alice2", string(sign))
	if err != nil {
		log.Printf("Set chaincode error: %v\n", err)
	}
	log.Printf("Set chaincode tx response:\ntx: %s\nresult: %v\n\n", resp.TransactionID, string(resp.Payload))

	time.Sleep(time.Second * 2)

	// send "key, msg, pkHex" to remote side...
	resp, err = verify(cli, "Alice2", string(msg), pkHex)
	if err != nil {
		log.Printf("Verify chaincode error: %v\n", err)
	}
	log.Printf("Verify chaincode tx response:\ntx: %s\nresult: %v\n\n", resp.TransactionID, string(resp.Payload))

	// handle at server side (in chaincode)
	b, err := sm2Verify2(msg, sign, pkHex)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Verify is %v\n", b)
}

func sm2Sign2(msg []byte, sk *sm2.PrivateKey) ([]byte, error) {
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

func sm2Verify2(msg, sign []byte, pkHex string) (bool, error) {
	if msg == nil || sign == nil {
		return false, errors.New("some args are nil")
	}
	if len(msg) == 0 || len(sign) == 0 || pkHex == "" {
		return false, errors.New("some args are empty")
	}
	publicKey, err := smutil.ReadPublicKeyFromHex(pkHex)
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

func sm3Ops2(cli *client.Client) {
	// handle at server side (in chaincode)
	msg := []byte("123456")
	hash := sm3.Sm3Sum(msg)
	hashHex := fmt.Sprintf("%02x", hash)
	fmt.Printf("digest:%s\n", hashHex)

	// send "key, value" to remote side...
	resp, err := digest(cli, "Alice2", string(msg))
	if err != nil {
		log.Printf("Digest chaincode error: %v\n", err)
	}
	log.Printf("Digest chaincode tx response:\ntx: %s\nresult: %v\n\n", resp.TransactionID, string(resp.Payload))

	time.Sleep(time.Second * 2)

	resp, err = get(cli, "Alice2")
	if err != nil {
		log.Printf("Get chaincode error: %v\n", err)
	}
	log.Printf("Get chaincode tx response:\ntx: %s\nresult: %v\n\n", resp.TransactionID, string(resp.Payload))
}

func sm4Ops2(cli *client.Client) {
	// handle at client side (in app server)
	k := []byte("1234567890abcdef")  // SM4 key size must be 16 bytes (128 bit)
	iv := []byte("0000000000000000") // SM4 iv size must be 16 bytes (128 bit)
	msg := []byte("123456")
	msgEncrypted, err := sm4Encrypt2(k, iv, msg)
	if err != nil {
		log.Fatalf("SM4 encrypt error:%v\n", err)
	}
	fmt.Printf("msgEncrypted:%02x\n", msgEncrypted)

	// invoke chaincode to set state
	// send "msgEncrypted" to remote side...
	resp, err := set(cli, "Charles", string(msgEncrypted))
	if err != nil {
		log.Printf("Set chaincode error: %v\n", err)
	}
	log.Printf("Set chaincode tx response:\ntx: %s\nresult: %v\n\n", resp.TransactionID, string(resp.Payload))

	time.Sleep(time.Second * 2)

	// invoke chaincode to get state
	// get "msgEncrypted" from remote side...
	resp, err = get(cli, "Charles")
	if err != nil {
		log.Printf("Verify chaincode error: %v\n", err)
	}
	log.Printf("Verify chaincode tx response:\ntx: %s\nresult: %02x\n\n", resp.TransactionID, resp.Payload)

	// handle at client side (in app server)
	//msgDecrypted, err := sm4Decrypt2(key, msgEncrypted)
	msgDecrypted, err := sm4Decrypt2(k, iv, resp.Payload)
	if err != nil {
		log.Fatalf("SM4 decrypt error:%v\n", err)
	}
	fmt.Printf("msgDecrypted:%s\n", msgDecrypted)
}

func sm4Encrypt2(key, iv, msg []byte) ([]byte, error) {
	if key == nil || iv == nil || msg == nil || len(key) != 16 || len(iv) != 16 || len(msg) == 0 {
		return nil, errors.New("some args are nil or empty")
	}
	// encrypt
	msgEncrypted, err := sm4.Sm4Encrypt(key, iv, msg)
	if err != nil {
		return nil, err
	}
	return msgEncrypted, nil
}

func sm4Decrypt2(key, iv, text []byte) ([]byte, error) {
	if key == nil || iv == nil || text == nil || len(key) != 16 || len(key) != 16 || len(text) == 0 {
		return nil, errors.New("some args are nil or empty")
	}
	// decrypt
	msgDecrypted, err := sm4.Sm4Decrypt(key, iv, text)
	if err != nil {
		return nil, err
	}
	return msgDecrypted, nil
}

// ------------------------------- Paillier --------------------------------------
func paillierCiphertext2(cli *client.Client) {
	publicKey, privateKey, err := key.NewKeyPair(1024, math.MaxInt64)
	if err != nil {
		log.Fatalf("New key pair error:%v\n", err)
	}
	// add using original operands
	var eX, eY *num.Int
	x := big.NewInt(100)
	y := big.NewInt(-20)
	eX = num.NewInt(publicKey, x)
	eY = num.NewInt(publicKey, y)
	// add using original operands
	sum := new(num.Int).AddCiphertext(eX, eY).Decrypt(privateKey)
	fmt.Printf("add ciphertext:%v\n", sum)
	diff := new(num.Int).SubCiphertext(eX, eY).Decrypt(privateKey)
	fmt.Printf("sub ciphertext:%v\n", diff)

	// Paillier Int to Hex String (serialize)
	eXStr, err := paillierutil.IntToHexStr(eX)
	if err != nil {
		log.Fatalf("Key (*num.Int) to Hex String error:%v\n", err)
	}
	fmt.Printf("eX HexStr:%s\n", eXStr) // 1026 characters
	eYStr, err := paillierutil.IntToHexStr(eY)
	if err != nil {
		log.Fatalf("Key (*num.Int) to Hex String error:%v\n", err)
	}
	fmt.Printf("eY HexStr:%s\n", eYStr) // 1026 characters

	// Hex string to Paillier Int (deserialize)
	eXNum, err := paillierutil.HexStrToInt(publicKey, eXStr)
	if err != nil {
		log.Fatalf("Hex string to key (*num.Int) error:%v\n", err)
	}
	eYNum, err := paillierutil.HexStrToInt(publicKey, eYStr)
	if err != nil {
		log.Fatalf("Hex string to key (*num.Int) error:%v\n", err)
	}
	// add using new operands
	sum2 := new(num.Int).AddCiphertext(eXNum, eYNum).Decrypt(privateKey)

	// invoke chaincode to set state
	// send "key, xHex" to remote side...
	resp, err := set(cli, "Danes", eXStr)
	if err != nil {
		log.Printf("Set chaincode error: %v\n", err)
	}
	log.Printf("Set chaincode tx response:\ntx: %s\nresult: %v\n\n", resp.TransactionID, string(resp.Payload))

	time.Sleep(time.Second * 2)

	// invoke chaincode using paillier tool
	// send "key, pkHex, yHex" to remote side...
	pkHex, err := paillierutil.MarshalPublicKeyHex(publicKey)
	if err != nil {
		log.Fatalf("Write public key to hex string error:%v\n", err)
	}
	resp, err = paillierCiphertext(cli, "Danes", pkHex, eYStr)
	if err != nil {
		log.Printf("PaillierCiphertext chaincode error: %v\n", err)
	}
	log.Printf("PaillierCiphertext chaincode tx response:\ntx: %s\nresult: %v\n\n", resp.TransactionID, string(resp.Payload))

	time.Sleep(time.Second * 2)

	// invoke chaincode after using paillier tool
	// get "result" from remote side...
	resp, err = get(cli, "Danes")
	if err != nil {
		log.Printf("Get chaincode error: %v\n", err)
	}
	log.Printf("Get chaincode tx response:\ntx: %s\nresult: %s\n\n", resp.TransactionID, string(resp.Payload))

	// decode result from chaincode
	sum3, err := paillierutil.HexStrToInt(publicKey, string(resp.Payload))
	if err != nil {
		log.Fatalf("Hex string to key (*num.Int) error:%v\n", err)
	}

	fmt.Printf("sum:%v, sum2:%v, sum3:%v\n", sum, sum2, sum3.Decrypt(privateKey))
}

func paillierPlaintext2(cli *client.Client) {
	publicKey, privateKey, err := key.NewKeyPair(1024, math.MaxInt64)
	if err != nil {
		log.Fatalf("New key pair error:%v\n", err)
	}
	var eX *num.Int
	x := big.NewInt(100)
	y := big.NewInt(-20)
	eX = num.NewInt(publicKey, x)
	// add using original operands
	sum := new(num.Int).AddPlaintext(eX, y).Decrypt(privateKey)
	fmt.Printf("add plaintext:%v\n", sum)
	product := new(num.Int).MulPlaintext(eX, y).Decrypt(privateKey)
	fmt.Printf("mul plaintext:%v\n", product)
	quotient := new(num.Int).DivPlaintext(eX, y).Decrypt(privateKey) // must be "x mod y == 0", avoid overflowing
	fmt.Printf("div plaintext:%v\n", quotient)

	// Paillier Int to Hex String (serialize)
	eXStr, err := paillierutil.IntToHexStr(eX)
	if err != nil {
		log.Fatalf("Key (*num.Int) to Hex String error:%v\n", err)
	}
	fmt.Printf("eX HexStr:%s\n", eXStr) // 1026 characters

	// Hex string to Paillier Int (deserialize)
	eXNum, err := paillierutil.HexStrToInt(publicKey, eXStr)
	if err != nil {
		log.Fatalf("Hex string to key (*num.Int) error:%v\n", err)
	}
	// add using new operands
	sum2 := new(num.Int).AddPlaintext(eXNum, y).Decrypt(privateKey)

	// invoke chaincode to set state
	// send "key, xHex" to remote side...
	resp, err := set(cli, "Danes", eXStr)
	if err != nil {
		log.Printf("Set chaincode error: %v\n", err)
	}
	log.Printf("Set chaincode tx response:\ntx: %s\nresult: %v\n\n", resp.TransactionID, string(resp.Payload))

	time.Sleep(time.Second * 2)

	// invoke chaincode using paillier tool
	// send "key, pkHex, yDec" to remote side...
	pkHex, err := paillierutil.MarshalPublicKeyHex(publicKey)
	if err != nil {
		log.Fatalf("Write public key to hex string error:%v\n", err)
	}
	resp, err = paillierPlaintext(cli, "Danes", pkHex, y.String())
	if err != nil {
		log.Printf("PaillierPlaintext chaincode error: %v\n", err)
	}
	log.Printf("PaillierPlaintext chaincode tx response:\ntx: %s\nresult: %v\n\n", resp.TransactionID, string(resp.Payload))

	time.Sleep(time.Second * 2)

	// invoke chaincode after using paillier tool
	// get "result" from remote side...
	resp, err = get(cli, "Danes")
	if err != nil {
		log.Printf("Get chaincode error: %v\n", err)
	}
	log.Printf("Get chaincode tx response:\ntx: %s\nresult: %s\n\n", resp.TransactionID, string(resp.Payload))

	// decode result from chaincode
	sum3, err := paillierutil.HexStrToInt(publicKey, string(resp.Payload))
	if err != nil {
		log.Fatalf("Hex string to key (*num.Int) error:%v\n", err)
	}

	fmt.Printf("sum:%v, sum2:%v, sum3:%v\n", sum, sum2, sum3.Decrypt(privateKey))
}
