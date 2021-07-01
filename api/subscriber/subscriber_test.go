package subscriber_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/infosum/statsd"
	"github.com/mullvad/wg-manager/api"
	"github.com/mullvad/wg-manager/api/subscriber"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

var fixture = subscriber.WireguardEvent{
	Action: "ADD",
	Peer: api.WireguardPeer{
		IPv4:   "10.99.0.1/32",
		IPv6:   "fc00:bbbb:bbbb:bb01::1/128",
		Ports:  []int{1234, 4321},
		Pubkey: strings.Repeat("a", 44),
	},
}

const (
	username = "testuser"
	password = "testpass"
)

func TestSubscriber(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != username || p != password {
			t.Fatal("invalid credentials")
		}

		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		err = wsjson.Write(ctx, c, fixture)
		if err != nil {
			t.Fatal(err)
		}

		c.Close(websocket.StatusNormalClosure, "")
	}))
	defer server.Close()

	parsedURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	metrics, err := statsd.New()
	if err != nil {
		t.Fatal(err)
	}

	s := subscriber.Subscriber{
		BaseURL:  "ws://" + parsedURL.Host,
		Channel:  "test",
		Username: username,
		Password: password,
		Metrics:  metrics,
	}

	// channel := make(chan subscriber.WireguardEvent, 1024)
	// defer close(channel)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	channel, err := s.Subscribe(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Try to recieve two messages
	// This will also test the reconnection logic, as the mock server closes the connection after sending the message
	for i := 0; i < 2; i++ {
		msg := <-channel
		if !reflect.DeepEqual(msg, fixture) {
			t.Errorf("got unexpected result, wanted %+v, got %+v", msg, fixture)
		}
	}
}

func TestSubscriberReconnect(t *testing.T) {
	var reject bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reject {
			return
		}

		u, p, ok := r.BasicAuth()
		if !ok || u != username || p != password {
			t.Fatal("invalid credentials")
		}

		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		err = wsjson.Write(ctx, c, fixture)
		if err != nil {
			t.Fatal(err)
		}

		c.Close(websocket.StatusNormalClosure, "")
		reject = true
	}))
	defer server.Close()

	parsedURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	metrics, err := statsd.New()
	if err != nil {
		t.Fatal(err)
	}

	s := subscriber.Subscriber{
		BaseURL:  "ws://" + parsedURL.Host,
		Channel:  "test",
		Username: username,
		Password: password,
		Metrics:  metrics,
	}

	//channel := make(chan subscriber.WireguardEvent, 1024)
	//defer close(channel)

	ctx, cancel := context.WithCancel(context.Background())

	channel, err := s.Subscribe(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Try to recieve two messages
	// This will also test the reconnection logic, as the mock server closes the connection after sending the message
	msg := <-channel
	if !reflect.DeepEqual(msg, fixture) {
		t.Errorf("got unexpected result, wanted %+v, got %+v", msg, fixture)
	}

	cancel()

	// Second read, blocks until context close
	<-channel
}
