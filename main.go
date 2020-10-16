package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/DMarby/jitter"
	"github.com/infosum/statsd"
	"github.com/jamiealquiza/envy"
	"github.com/mullvad/wg-manager/api"
	"github.com/mullvad/wg-manager/api/subscriber"
	"github.com/mullvad/wg-manager/portforward"
	"github.com/mullvad/wg-manager/wireguard"
)

var (
	a          *api.API
	wg         *wireguard.Wireguard
	pf         *portforward.Portforward
	metrics    *statsd.Client
	appVersion string // Populated during build time
)

func main() {
	// Set up commandline flags
	interval := flag.Duration("interval", time.Minute, "how often wireguard peers will be synchronized with the api")
	delay := flag.Duration("delay", time.Second*45, "max random delay for the synchronization")
	apiTimeout := flag.Duration("api-timeout", time.Second*30, "max duration for API requests")
	url := flag.String("url", "https://example.com", "api url")
	username := flag.String("username", "", "api username")
	password := flag.String("password", "", "api password")
	hostname := flag.String("hostname", "", "server hostname")
	interfaces := flag.String("interfaces", "wg0", "wireguard interfaces to configure. Pass a comma delimited list to configure multiple interfaces, eg 'wg0,wg1,wg2'")
	portForwardingChainPrefix := flag.String("portforwarding-chain-prefix", "PORTFORWARDING", "iptables chain prefix to use for portforwarding, will create 'NAME_TCP' and 'NAME_UDP' chains")
	portForwardingIpsetIPv4 := flag.String("portforwarding-ipset-ipv4", "PORTFORWARDING_IPV4", "ipset table to use for portforwarding for ipv4 addresses.")
	portForwardingIpsetIPv6 := flag.String("portforwarding-ipset-ipv6", "PORTFORWARDING_IPV6", "ipset table to use for portforwarding for ipv6 addresses.")
	statsdAddress := flag.String("statsd-address", "127.0.0.1:8125", "statsd address to send metrics to")
	mqURL := flag.String("mq-url", "wss://example.com/mq", "message-queue url")
	mqUsername := flag.String("mq-username", "", "message-queue username")
	mqPassword := flag.String("mq-password", "", "message-queue password")
	mqChannel := flag.String("mq-channel", "wireguard", "message-queue channel")

	// Parse environment variables
	envy.Parse("WG")

	// Add flag to output the version
	version := flag.Bool("v", false, "prints current app version")

	// Parse commandline flags
	flag.Parse()

	if *version {
		fmt.Println(appVersion)
		os.Exit(0)
	}

	log.Printf("starting wg-manager %s", appVersion)

	// Initialize metrics
	var err error
	metrics, err = statsd.New(statsd.TagsFormat(statsd.Datadog), statsd.Prefix("wireguard"), statsd.Address(*statsdAddress))
	if err != nil {
		log.Fatalf("Error initializing metrics %s", err)
	}
	defer metrics.Close()

	// Initialize the API
	a = &api.API{
		Username: *username,
		Password: *password,
		BaseURL:  *url,
		Hostname: *hostname,
		Client: &http.Client{
			Timeout: *apiTimeout,
		},
	}

	// Initialize Wireguard
	if *interfaces == "" {
		log.Fatalf("no wireguard interfaces configured")
	}

	interfacesList := strings.Split(*interfaces, ",")

	wg, err = wireguard.New(interfacesList, metrics)
	if err != nil {
		log.Fatalf("error initializing wireguard %s", err)
	}
	defer wg.Close()

	// Initialize portforward
	pf, err = portforward.New(*portForwardingChainPrefix, *portForwardingIpsetIPv4, *portForwardingIpsetIPv6)
	if err != nil {
		log.Fatalf("error initializing portforwarding %s", err)
	}

	// Set up context for shutting down
	shutdownCtx, shutdown := context.WithCancel(context.Background())
	defer shutdown()

	// Run an initial synchronization
	synchronize()

	// Set up a connection to receive add/remove events
	s := subscriber.Subscriber{
		Username: *mqUsername,
		Password: *mqPassword,
		BaseURL:  *mqURL,
		Channel:  *mqChannel,
		Metrics:  metrics,
	}
	eventChannel := make(chan subscriber.WireguardEvent)
	defer close(eventChannel)

	err = s.Subscribe(shutdownCtx, eventChannel)
	if err != nil {
		log.Fatal("error connecting to message-queue", err)
	}

	// Create a ticker to run our logic for polling the api and updating wireguard peers
	ticker := jitter.NewTicker(*interval, *delay)
	go func() {
		for {
			select {
			case msg := <-eventChannel:
				handleEvent(msg)
			case <-ticker.C:
				// We run this synchronously, the ticker will drop ticks if this takes too long
				// This way we don't need a mutex or similar to ensure it doesn't run concurrently either
				synchronize()
			case <-shutdownCtx.Done():
				ticker.Stop()
				return
			}
		}
	}()

	// Wait for shutdown or error
	err = waitForInterrupt(shutdownCtx)
	log.Printf("shutting down: %s", err)
}

func handleEvent(event subscriber.WireguardEvent) {
	switch event.Action {
	case "ADD":
		wg.AddPeer(event.Peer)
		pf.AddPortforwarding(event.Peer)
	case "REMOVE":
		wg.RemovePeer(event.Peer)
		pf.RemovePortforwarding(event.Peer)
	default: // Bad data from the API, ignore it
	}
}

func synchronize() {
	defer metrics.NewTiming().Send("synchronize_time")

	t := metrics.NewTiming()
	peers, err := a.GetWireguardPeers()
	if err != nil {
		metrics.Increment("error_getting_peers")
		log.Printf("error getting peers %s", err.Error())
		return
	}
	t.Send("get_wireguard_peers_time")

	t = metrics.NewTiming()
	connectedKeys := wg.UpdatePeers(peers)
	t.Send("update_peers_time")

	t = metrics.NewTiming()
	pf.UpdatePortforwarding(peers)
	t.Send("update_portforwarding_time")

	t = metrics.NewTiming()
	err = a.PostWireguardConnections(connectedKeys)
	if err != nil {
		metrics.Increment("error_posting_connections")
		log.Printf("error posting connections %s", err.Error())
		return
	}
	t.Send("post_wireguard_connections_time")
}

func waitForInterrupt(ctx context.Context) error {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-c:
		return fmt.Errorf("received signal %s", sig)
	case <-ctx.Done():
		return errors.New("canceled")
	}
}
