package subscriber

import (
	"context"
	"encoding/base64"
	"log"
	"net/http"
	"time"

	"github.com/infosum/statsd"
	"github.com/mullvad/wg-manager/api"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

// Subscriber is a utility for receiving wireguard key events from a message-queue server
type Subscriber struct {
	Username string
	Password string
	BaseURL  string
	Channel  string
	Metrics  *statsd.Client

	conn    *websocket.Conn
	eventCh chan WireguardEvent
}

// WireguardEvent is a wireguard key event
type WireguardEvent struct {
	Action string            `json:"action"`
	Peer   api.WireguardPeer `json:"peer"`
}

const subProtocol = "message-queue-v1"

// Subscribe establishes a websocket connection for a message-queue channel, and emits messages on the given channel
func (s *Subscriber) Subscribe(ctx context.Context) (chan WireguardEvent, error) {
	s.eventCh = make(chan WireguardEvent, 1024)

	err := s.connect(ctx)

	if err != nil {
		return s.eventCh, err
	}

	go s.read(ctx)

	return s.eventCh, nil
}

func (s *Subscriber) connect(ctx context.Context) error {
	header := http.Header{}

	if s.Username != "" && s.Password != "" {
		header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(s.Username+":"+s.Password)))
	}

	conn, _, err := websocket.Dial(ctx, s.BaseURL+"/channel/"+s.Channel, &websocket.DialOptions{
		Subprotocols: []string{subProtocol},
		HTTPHeader:   header,
	})

	if err != nil {
		return err
	}

	s.conn = conn

	return nil
}

func (s *Subscriber) read(ctx context.Context) {
	for {
		v := WireguardEvent{}
		err := wsjson.Read(ctx, s.conn, &v)
		if err != nil {
			log.Println("error reading from websocket, reconnecting", err)
			s.Metrics.Increment("websocket_error")

			// Make sure the connection is closed
			s.conn.Close(websocket.StatusInternalError, "")

			// Start attempting to reconnect
			err = s.reconnect(ctx)
			if err != nil { // Reconnect failed (context closed)
				close(s.eventCh)
				return
			}

			continue
		}

		s.eventCh <- v
	}
}

// reconnect try to init a new connection unless the context is closed
func (s *Subscriber) reconnect(ctx context.Context) error {
	ticker := time.NewTicker(1 * time.Second)

	var err error
	for {
		select {
		case <-ticker.C:
			err = s.connect(ctx)
			if err == nil {
				log.Println("successfully reconnected to websocket")
				s.Metrics.Increment("websocket_reconnect_success")
				return nil
			}
			s.Metrics.Increment("websocket_reconnect_error")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
