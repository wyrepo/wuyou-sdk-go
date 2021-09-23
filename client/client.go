package client

import (
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"log"
)

type Client struct {
	ConfigPath string
	Channel    string
	OrgUser    string
	SDK        *fabsdk.FabricSDK
	CC         *channel.Client
}

func New(path, channel, user string) *Client {
	c := &Client{
		ConfigPath: path,
		Channel:    channel,
		OrgUser:    user,
	}
	sdk, err := fabsdk.New(config.FromFile(c.ConfigPath))
	if err != nil {
		log.Panicf("failed to create fabric sdk: %s", err)
	}
	c.SDK = sdk
	c.CC = NewSdkClient(sdk, c.Channel, c.OrgUser)
	return c
}

func NewSdkClient(sdk *fabsdk.FabricSDK, channelID, OrgUser string) (cc *channel.Client) {
	ccp := sdk.ChannelContext(channelID, fabsdk.WithUser(OrgUser))
	cc, err := channel.New(ccp)
	if err != nil {
		log.Panicf("failed to create channel client: %s", err)
	}
	return cc
}

func (c *Client) Close() {
	c.SDK.Close()
}
