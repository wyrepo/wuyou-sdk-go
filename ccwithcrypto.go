package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/protos/ledger/queryresult"
	"github.com/hyperledger/fabric/protos/peer"
	"github.com/wyrepo/wuyou-crypto-go/paillier/num"
	paillierutil "github.com/wyrepo/wuyou-crypto-go/paillier/util"
	"github.com/wyrepo/wuyou-crypto-go/sm/sm3"
	smutil "github.com/wyrepo/wuyou-crypto-go/sm/util"
	"log"
	"math/big"
	"os"
)

var logger = log.New(os.Stdout, "", log.LstdFlags|log.LUTC|log.Lshortfile)

type SimpleStorageChainCode struct{}

func (s *SimpleStorageChainCode) Init(stub shim.ChaincodeStubInterface) peer.Response {
	return shim.Success(nil)
}

func (s *SimpleStorageChainCode) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	fnc, args := stub.GetFunctionAndParameters()
	switch fnc {
	case "get":
		return s.get(stub, args)
	case "put":
		return s.put(stub, args)
	case "set":
		return s.set(stub, args)
	case "history":
		return s.history(stub, args)
	case "verify":
		return s.verify(stub, args)
	case "digest":
		return s.digest(stub, args)
	case "paillierCiphertext":
		return s.paillierCiphertext(stub, args)
	case "paillierPlaintext":
		return s.paillierPlaintext(stub, args)
	default:
		return shim.Error("Invalid function name, support 'get', 'put', 'set', 'history'")
	}
}

func (s *SimpleStorageChainCode) get(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 1 {
		return shim.Error("Invalid argument, require <key>")
	}
	key := args[0]
	value, err := stub.GetState(key)
	if err != nil {
		logger.Printf("Get key %s from ledger failed: %s\n", key, err)
		return shim.Error(fmt.Sprintf("GetState error %v", err))
	}
	logger.Printf("Got key %s from ledger\n", key)
	return shim.Success(value)
}

func (s *SimpleStorageChainCode) put(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 2 {
		return shim.Error("Invalid argument, require <key> and <value>")
	}
	key := args[0]
	value := args[1]
	val, err := stub.GetState(key)
	if err != nil {
		logger.Printf("Check key %s whether exists in ledger failed: %s\n", key, err)
		return shim.Error(fmt.Sprintf("GetState error %v", err))
	}
	if val != nil {
		logger.Printf("Put key %s failed: already exists\n", key)
		return shim.Error(fmt.Sprintf("Key %s already exists", key))
	}
	err = stub.PutState(key, []byte(value))
	if err != nil {
		logger.Printf("Put key %s failed: %s\n", key, err)
		return shim.Error(fmt.Sprintf("PutState error %v", err))
	}
	logger.Printf("Put key %s into ledger\n", key)
	return shim.Success([]byte(key))
}

func (s *SimpleStorageChainCode) set(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 2 {
		return shim.Error("Invalid argument, require <key> and <value>")
	}
	key := args[0]
	value := args[1]
	err := stub.PutState(key, []byte(value))
	if err != nil {
		logger.Printf("Set key %s failed: %s\n", key, err)
		return shim.Error(fmt.Sprintf("PutState error %v", err))
	}
	logger.Printf("Set key %s in ledger\n", key)
	return shim.Success([]byte(key))
}
func (s *SimpleStorageChainCode) history(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 1 {
		return shim.Error("Invalid argument, require <key>")
	}
	key := args[0]
	iter, err := stub.GetHistoryForKey(key)
	if err != nil {
		logger.Printf("Get history for key %s failed: %s\n", key, err)
		return shim.Error(fmt.Sprintf("GetHistoryForKey error %v", err))
	}
	var result []*queryresult.KeyModification
	for iter.HasNext() {
		item, err := iter.Next()
		if err != nil {
			logger.Printf("Iter to next hisotry failed: %s\n", err)
			return shim.Error(fmt.Sprintf("Iter to next error %v", err))
		}
		result = append(result, item)
	}
	data, err := json.Marshal(result)
	if err != nil {
		logger.Printf("Marshl history result to json failed: %s\n", err)
		return shim.Error(fmt.Sprintf("Marshl history result error %v", err))
	}
	logger.Printf("Got key %s hisotry in ledger\n", key)
	return shim.Success(data)
}

func (s *SimpleStorageChainCode) verify(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 3 {
		return shim.Error("Invalid argument, require <key>")
	}
	key := args[0]
	msg := []byte(args[1])
	pkHex := args[2]
	sign, err := stub.GetState(key)
	if err != nil {
		logger.Printf("Check key %s whether exists in ledger failed: %s\n", key, err)
		return shim.Error(fmt.Sprintf("GetState error %v", err))
	}
	if sign == nil || len(sign) == 0 {
		logger.Printf("Signature of key %s is nil or empty\n", key)
		return shim.Error(fmt.Sprintf("Signature of key %s is nil or empty", key))
	}
	pk, err := smutil.ReadPublicKeyFromHex(pkHex)
	if err != nil {
		logger.Printf("Read public key %s failed: %s\n", pkHex, err)
		return shim.Error(fmt.Sprintf("Read public key failed %v", err))
	}
	// verify
	ok := pk.Verify(msg, sign)
	if ok {
		logger.Printf("Verify signature of key %s is OK\n", key)
		return shim.Success([]byte("true"))
	} else {
		logger.Printf("Verify signature of key %s failed\n", key)
		return shim.Error(fmt.Sprintf("Verify signature of key %s failed\n", key))
	}
}

func (s *SimpleStorageChainCode) digest(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 2 {
		return shim.Error("Invalid argument, require <key> and <value>")
	}
	key := args[0]
	value := args[1]
	// digest
	hash := sm3.Sm3Sum([]byte(value))
	//hashHex := fmt.Sprintf("%02x", hash)
	hashHex := hex.EncodeToString(hash)
	logger.Printf("digest:%s\n", hashHex)
	err := stub.PutState(key, []byte(value+"@@"+hashHex))
	if err != nil {
		logger.Printf("Set key %s with digest failed: %s\n", key, err)
		return shim.Error(fmt.Sprintf("PutState with digest error %v", err))
	}
	logger.Printf("Set key %s with digest into ledger\n", key)
	return shim.Success([]byte(key))
}

func (s *SimpleStorageChainCode) paillierCiphertext(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 3 {
		return shim.Error("Invalid argument, require <key> and <value>")
	}
	key := args[0]
	xHexBytes, err := stub.GetState(key)
	if err != nil {
		logger.Printf("Check key %s whether exists in ledger failed: %s\n", key, err)
		return shim.Error(fmt.Sprintf("GetState error %v", err))
	}
	if xHexBytes == nil || len(xHexBytes) == 0 {
		logger.Printf("Value of key %s is nil or empty\n", key)
		return shim.Error(fmt.Sprintf("Value of key %s is nil or empty", key))
	}
	pkHex := args[1]
	pk, err := paillierutil.UnmarshalPublicKeyHex(pkHex)
	if err != nil {
		logger.Printf("Unmarshal public key %s failed: %s\n", pkHex, err)
		return shim.Error(fmt.Sprintf("Public key unmarshal error %v", err))
	}
	yHex := args[2]
	y, err := paillierutil.HexStrToInt(pk, yHex)
	if err != nil {
		logger.Printf("Y Hex string to paillier number failed: %s\n", err)
		return shim.Error(fmt.Sprintf("Y Hex string to paillier number error:%v", err))
	}
	x, err := paillierutil.HexStrToInt(pk, string(xHexBytes))
	if err != nil {
		logger.Printf("X Hex string to paillier number failed: %s\n", err)
		return shim.Error(fmt.Sprintf("X Hex string to paillier number error:%v", err))
	}
	// add ciphertext
	sum := new(num.Int).AddCiphertext(x, y)
	sumHex, _ := paillierutil.IntToHexStr(sum)
	logger.Printf("Paillier AddCiphertext sum:%s\n", sumHex)
	// sub ciphertext
	diff := new(num.Int).SubCiphertext(x, y)
	diffHex, _ := paillierutil.IntToHexStr(diff)
	logger.Printf("Paillier SubCiphertext diff:%s\n", diffHex)
	// just put "sum", ignoring "diff"
	err = stub.PutState(key, []byte(sumHex))
	if err != nil {
		logger.Printf("Put key %s failed: %s\n", key, err)
		return shim.Error(fmt.Sprintf("PutState error %v", err))
	}
	logger.Printf("Paillier Ciphertext handling, put key %s into ledger\n", key)
	return shim.Success([]byte(key))
}

func (s *SimpleStorageChainCode) paillierPlaintext(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) != 3 {
		return shim.Error("Invalid argument, require <key> and <value>")
	}
	key := args[0]
	xHexBytes, err := stub.GetState(key)
	if err != nil {
		logger.Printf("Check key %s whether exists in ledger failed: %s\n", key, err)
		return shim.Error(fmt.Sprintf("GetState error %v", err))
	}
	if xHexBytes == nil || len(xHexBytes) == 0 {
		logger.Printf("Value of key %s is nil or empty\n", key)
		return shim.Error(fmt.Sprintf("Value of key %s is nil or empty", key))
	}
	pkHex := args[1]
	pk, err := paillierutil.UnmarshalPublicKeyHex(pkHex)
	if err != nil {
		logger.Printf("Unmarshal public key %s failed: %s\n", pkHex, err)
		return shim.Error(fmt.Sprintf("Public key unmarshal error %v", err))
	}
	yDec := args[2] // decimal operand
	y, ok := new(big.Int).SetString(yDec, 10)
	if !ok {
		logger.Printf("Check decimal operand %s failed\n", yDec)
		return shim.Error(fmt.Sprintf("Operand converting error"))
	}
	x, err := paillierutil.HexStrToInt(pk, string(xHexBytes))
	if err != nil {
		logger.Printf("X Hex string to paillier number failed: %s\n", err)
		return shim.Error(fmt.Sprintf("X Hex string to paillier number error:%v", err))
	}
	// add plaintext
	sum := new(num.Int).AddPlaintext(x, y)
	sumHex, _ := paillierutil.IntToHexStr(sum)
	logger.Printf("Paillier AddPlaintext sum:%s\n", sumHex)
	// mul plaintext
	product := new(num.Int).MulPlaintext(x, y)
	productHex, _ := paillierutil.IntToHexStr(product)
	logger.Printf("Paillier MulPlaintext product:%s\n", productHex)
	// div plaintext
	quotient := new(num.Int).DivPlaintext(x, y) // must be "x mod y == 0", avoid overflowing
	quotientHex, _ := paillierutil.IntToHexStr(quotient)
	logger.Printf("Paillier DivPlaintext quotient:%s\n", quotientHex)
	// just put "sum", ignoring "diff"
	err = stub.PutState(key, []byte(sumHex))
	if err != nil {
		logger.Printf("Put key %s failed: %s\n", key, err)
		return shim.Error(fmt.Sprintf("PutState error %v", err))
	}
	logger.Printf("Paillier Plaintext handling, put key %s into ledger\n", key)
	return shim.Success([]byte(key))
}

func main() {
	err := shim.Start(new(SimpleStorageChainCode))
	if err != nil {
		fmt.Printf("Error starting Simple chaincode: %s", err)
	}
}
