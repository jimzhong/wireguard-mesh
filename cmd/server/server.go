package main

import (
	"encoding/gob"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jimzhong/wireguard-overlay/internal/config"
	"github.com/jimzhong/wireguard-overlay/internal/wg"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func startHttpServer(wgState *wg.State, port int) *http.Server {
	mux := http.NewServeMux()
	c := cache.New(5*time.Second, time.Minute)
	mux.HandleFunc("/",
		func(w http.ResponseWriter, request *http.Request) {
			peers, found := c.Get("")
			logrus.Debug("Cache found: ", found)
			if !found {
				ps, _ := wgState.GetPeers()
				for i := range ps {
					// Clients should not see these fields
					ps[i].KeepaliveInterval = 0
					ps[i].PresharedKey = wgtypes.Key{}
				}
				peers = ps
				c.Set("", peers, cache.DefaultExpiration)
			}
			logrus.Debug("Peers: ", peers)
			if peers == nil {
				logrus.Error("Could not get wireguard peers")
				return
			}
			err := gob.NewEncoder(w).Encode(peers)
			if err != nil {
				logrus.WithError(err).Error("Could not encode peers")
			}
		})
	addr := net.TCPAddr{
		IP:   wgState.OverlayAddr.IP,
		Port: port,
	}
	server := &http.Server{
		Addr:         addr.String(),
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 6 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      mux,
	}
	go func() {
		if err := server.ListenAndServe(); err != nil {
			logrus.WithError(err).Fatal("Could not start server")
		}
	}()
	return server
}

func main() {
	config, err := config.LoadServerConfig()
	if err != nil {
		logrus.Fatal(err)
	}
	logLevel, err := logrus.ParseLevel(config.LogLevel)
	if err != nil {
		logrus.WithError(err).Fatal("Could not parse loglevel")
	}
	logrus.SetLevel(logLevel)

	wgState, err := wg.New(config.Interface, config.Port, (net.IPNet)(*config.OverlayNet), config.PrivateKey)
	if err != nil {
		logrus.WithError(err).Fatal("Could not instantiate wireguard controller")
	}
	if err := wgState.SetUpInterface(); err != nil {
		logrus.WithError(err).Fatal("Could not up interface")
	}
	defer func() {
		logrus.Info("Exiting...")
		if err := wgState.DownInterface(); err != nil {
			logrus.WithError(err).Error("Could not down interface")
		}
	}()

	peers := make([]wg.Peer, 0, len(config.ClientPubkeys))
	for _, p := range config.ClientPubkeys {
		pubkey, err := wgtypes.ParseKey(p)
		if err != nil {
			logrus.WithError(err).Warn("Skipped invalid key: ", p)
			continue
		}
		peers = append(peers, wg.Peer{PublicKey: pubkey})
	}
	logrus.Debug("Adding peers: ", peers)
	if err = wgState.AddPeers(peers); err != nil {
		logrus.WithError(err).Error("Could not add peers")
	}
	startHttpServer(wgState, config.Port)
	logrus.Info("Server is running. Pubkey: ", wgState.PublicKey)

	incomingSigs := make(chan os.Signal, 1)
	signal.Notify(incomingSigs, syscall.SIGTERM, os.Interrupt)
	<-incomingSigs
}
