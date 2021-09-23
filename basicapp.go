package main

import (
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/wyrepo/wuyou-sdk-go/client"
	"log"
	"time"
)

func main() {
	var (
		configPath    = "config.yaml"
		channelName   = "mychannel"
		userName      = "User1"
		chaincodeName = "crypto"
	)

	cli := client.New(configPath, channelName, userName)
	defer cli.Close()

	reqSet := channel.Request{
		ChaincodeID: chaincodeName,
		Fcn:         "set",
		Args:        [][]byte{[]byte("Alice"), []byte("says hello")},
	}

	reqGet := channel.Request{
		ChaincodeID: chaincodeName,
		Fcn:         "get",
		Args:        [][]byte{[]byte("Alice")},
	}

	// send request and handle resp
	resp, err := cli.CC.Execute(reqSet)
	if err != nil {
		log.Panicf("Set chaincode error: %v", err)
	}
	log.Printf("Set chaincode tx resp:\ntx: %s\nresult: %v\n\n", resp.TransactionID, string(resp.Payload))

	time.Sleep(time.Second * 2)

	//resp, err = cli.CC.Execute(reqGet) // will create a transaction
	resp, err = cli.CC.Query(reqGet) // will not create a transaction
	if err != nil {
		log.Panicf("Get chaincode error: %v", err)
	}

	log.Printf("Get chaincode tx resp:\ntx: %s\nresult: %v\n\n", resp.TransactionID, string(resp.Payload))

	log.Println("Query chaincode success on peer0.org44")
}
