// The JSON shapes this package's routes read and write, kept in this file alone so clients generate their
// TypeScript types from it with tygo; every other type here is internal.

package devtunnels

import "time"

type AccountStatus struct {
	Connected   bool      `json:"connected"`
	Provider    string    `json:"provider,omitempty"`
	Account     string    `json:"account,omitempty"`
	ConnectedAt time.Time `json:"connectedAt,omitzero"`
}

type AuthorizationStart struct {
	Handle           string `json:"handle"`
	UserCode         string `json:"userCode"`
	VerificationURI  string `json:"verificationUri"`
	ExpiresInSeconds int64  `json:"expiresInSeconds"`
	IntervalSeconds  int64  `json:"intervalSeconds"`
}

type AuthorizationPoll struct {
	Status          string `json:"status"`
	IntervalSeconds int64  `json:"intervalSeconds,omitempty"`
	AccountStatus   `tstype:",extends"`
}

type AuthorizationRequest struct {
	Provider string `json:"provider"`
}
