// The JSON frames of the interactive SSH authentication WebSocket, kept in this file alone so clients generate their
// TypeScript types from it with tygo.

package ssh

type ClientFrame struct {
	Type string `json:"type"`
	Cols uint16 `json:"cols,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
}

type ServerFrame struct {
	Type    string `json:"type"`
	Code    *int   `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}
