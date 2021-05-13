package main

import (
	"bytes"
	"encoding/gob"
	"errors"
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

func newHttpServer(wgState *wg.State, port int) *http.Server {
	mux := http.NewServeMux()
	c := cache.New(5*time.Second, time.Minute)
	mux.HandleFunc("/",
		func(w http.ResponseWriter, request *http.Request) {
			cached, found := c.Get("")
			logrus.Debug("Cache hit: ", found)
			var serialized []byte
			if found {
				var ok bool
				serialized, ok = cached.([]byte)
				if !ok {
					http.Error(w, "Could not read serialized peers", http.StatusInternalServerError)
				}
			} else {
				peers, _ := wgState.GetPeers()
				for i := range peers {
					// Clients should not see these fields
					peers[i].KeepaliveInterval = 0
					peers[i].PresharedKey = wgtypes.Key{}
				}
				var buf bytes.Buffer
				if err := gob.NewEncoder(&buf).Encode(peers); err != nil {
					http.Error(w, "Could not serialize peers", http.StatusInternalServerError)
					return
				}
				serialized = buf.Bytes()
				c.SetDefault("", serialized)
			}
			if serialized == nil {
				http.Error(w, "Could not get serialized peers", http.StatusInternalServerError)
				return
			}
			_, err := w.Write(serialized)
			if err != nil {
				logrus.WithError(err).Error("Could not write response")
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

	server := newHttpServer(wgState, config.Port)
	defer server.Close()
	go func() {
		if err := server.ListenAndServe(); err != nil && errors.Is(err, http.ErrServerClosed) {
			logrus.WithError(err).Fatal("Could not start server")
		}
	}()
	logrus.Info("Server is running. Pubkey: ", wgState.PublicKey)

	incomingSigs := make(chan os.Signal, 1)
	signal.Notify(incomingSigs, syscall.SIGTERM, os.Interrupt)
	<-incomingSigs
}
