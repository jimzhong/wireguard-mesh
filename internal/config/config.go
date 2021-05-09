package config

import (
	"fmt"
	"net"

	"github.com/stevenroose/gonfig"
)

// type base_config struct {
// 	OverlayNet *network `id:"overlay-net" desc:"the network in which to allocate addresses for the overlay network (CIDR format)" default:"fd80:dead:beef:1234::/64"`
// 	Interface  string   `desc:"name of the wireguard interface to create and manage" default:"wgoverlay"`
// 	LogLevel   string   `id:"log-level" desc:"set the verbosity (debug/info/warn/error)" default:"warn"`
// 	PrivateKey string   `id:"private-key" desc:"private key for wireguard; must be 32 bytes base64 encoded;"`
// }

type client_config struct {
	ConfigFile   string   `id:"config" desc:"config file"`
	OverlayNet   *network `id:"overlay-net" desc:"the network in which to allocate addresses for the overlay network (CIDR format)" default:"fd80:dead:beef:1234::/64"`
	Interface    string   `desc:"name of the wireguard interface to create and manage" default:"wgoverlay"`
	LogLevel     string   `id:"log-level" desc:"set the verbosity (debug/info/warn/error)" default:"info"`
	PrivateKey   string   `id:"private-key" desc:"private key for wireguard; must be 32 bytes base64 encoded;"`
	ServerAddr   *net.IP  `id:"server-addr" desc:"IP address of the server"`
	ServerPort   int      `id:"port" desc:"server's wireguard port (UDP) and peer query port (TCP)" default:"54321"`
	ServerPubkey string   `id:"server-pubkey" desc:"base64 encoded public key of the server"`
	PresharedKey string   `id:"preshared-key" desc:"base64 encoded symmetric encryption for data communication between clients"`
}

type server_config struct {
	ConfigFile    string   `id:"config" desc:"config file"`
	OverlayNet    *network `id:"overlay-net" desc:"the network in which to allocate addresses for the overlay network (CIDR format)" default:"fd80:dead:beef:1234::/64"`
	Interface     string   `desc:"name of the wireguard interface to create and manage" default:"wgoverlay"`
	LogLevel      string   `id:"log-level" desc:"set the verbosity (debug/info/warn/error)" default:"info"`
	PrivateKey    string   `id:"private-key" desc:"private key for wireguard; must be 32 bytes base64 encoded;"`
	Port          int      `id:"port" desc:"wireguard listen port (UDP) and peer query listen port (TCP)" default:"54321"`
	ClientPubkeys []string `id:"client-pubkeys" desc:"base64 encoded public keys of the clients"`
}

func LoadServerConfig() (*server_config, error) {
	var config server_config
	err := gonfig.Load(&config, gonfig.Conf{
		ConfigFileVariable:  "config",
		FileDecoder:         gonfig.DecoderJSON,
		FileDefaultFilename: "/etc/wireguard-overlay/server.json",
		EnvDisable:          true})
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func LoadClientConfig() (*client_config, error) {
	var config client_config
	err := gonfig.Load(&config, gonfig.Conf{
		ConfigFileVariable:  "config",
		FileDecoder:         gonfig.DecoderJSON,
		FileDefaultFilename: "/etc/wireguard-overlay/client.json",
		EnvDisable:          true})
	if err != nil {
		return nil, err
	}
	return &config, nil
}

type network net.IPNet

// UnmarshalText parses the provided byte array into the network receiver
func (n *network) UnmarshalText(data []byte) error {
	_, ipnet, err := net.ParseCIDR(string(data))
	if err != nil {
		return err
	}
	if ones, _ := ipnet.Mask.Size(); ones%8 != 0 {
		return fmt.Errorf("unsupported overlay network size; net mask must be multiple of 8, got %d", ones)
	}
	*n = network(*ipnet)
	return nil
}
