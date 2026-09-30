// Every cs-plane WebSocket negotiates one versioned subprotocol and takes its credential as a second, prefixed one,
// since a browser cannot set WebSocket headers. Upgrader admits any Origin because each route checks Origins first.
package security

import (
	"net/http"
	"slices"
	"strings"

	"github.com/gorilla/websocket"
)

const WebSocketProtocol = "cybershuttle.v1"

var Upgrader = websocket.Upgrader{Subprotocols: []string{WebSocketProtocol}, CheckOrigin: func(*http.Request) bool { return true }}

// SubprotocolCredential returns the prefixed credential from an offer of exactly it and WebSocketProtocol, any order.
func SubprotocolCredential(protocols []string, prefix string) (string, bool) {
	i := slices.Index(protocols, WebSocketProtocol)
	if len(protocols) != 2 || i < 0 {
		return "", false
	}
	return strings.CutPrefix(protocols[1-i], prefix)
}
