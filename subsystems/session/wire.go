// The JSON shapes this package's routes read and write, kept in this file alone so clients generate their
// TypeScript types from it with tygo; every other type here is internal.

package session

import "time"

type Gres struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type Partition struct {
	Name     string `json:"name"`
	CPUCount int    `json:"cpuCount"`
	MemoryMB int    `json:"memoryMb"`
	GRES     []Gres `json:"gres"`
}

type Resource struct {
	Alias      string      `json:"alias"`
	Accounts   []string    `json:"accounts"`
	Partitions []Partition `json:"partitions"`
	HomeDir    string      `json:"homeDir"`
}

type Resources struct {
	Cores       int    `json:"cores"`
	MemoryMB    int    `json:"memoryMb"`
	WallMinutes int    `json:"wallMinutes"`
	GPUType     string `json:"gpuType,omitempty"`
	GPUCount    int    `json:"gpuCount,omitempty"`
}

type CreateRequest struct {
	ID             string    `json:"-"`
	IdempotencyKey string    `json:"idempotencyKey,omitempty"`
	Alias          string    `json:"alias"`
	Account        string    `json:"account,omitempty"`
	Partition      string    `json:"partition"`
	RootFolder     string    `json:"rootFolder"`
	Resources      Resources `json:"resources"`
	TunnelModes    []string  `json:"tunnelModes,omitempty"`
}

type SessionResponse struct {
	ID          string    `json:"id"`
	Seq         int       `json:"seq"`
	State       string    `json:"state"`
	Platform    string    `json:"platform"`
	Alias       string    `json:"alias"`
	Account     string    `json:"account,omitempty"`
	Partition   string    `json:"partition"`
	RootFolder  string    `json:"rootFolder"`
	Resources   Resources `json:"resources"`
	TunnelModes []string  `json:"tunnelModes"`
	Error       string    `json:"error,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	StartedAt   time.Time `json:"startedAt,omitzero"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type SessionList struct {
	Sessions []SessionResponse `json:"sessions"`
	Logs     []SessionLogTail  `json:"logs"`
}

type LinkAccess struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

type DevtunnelAccess struct {
	ID        string `json:"id"`
	Cluster   string `json:"cluster"`
	HostToken string `json:"hostToken"`
}

type AttachResponse struct {
	Session   SessionResponse  `json:"session"`
	Port      uint16           `json:"port"`
	Link      *LinkAccess      `json:"link,omitempty"`
	Devtunnel *DevtunnelAccess `json:"devtunnel,omitempty"`
}

type SessionAccessResponse struct {
	SessionID string               `json:"sessionId"`
	Seq       int                  `json:"seq"`
	ExpiresAt time.Time            `json:"expiresAt"`
	Jupyter   SessionJupyterAccess `json:"jupyter"`
}

type SessionJupyterAccess struct {
	URI   string `json:"uri"`
	Token string `json:"token"`
}

type ValidationResult struct {
	SessionID string `json:"sessionId"`
	Script    string `json:"script"`
	Status    string `json:"status"`
	Message   string `json:"message"`
	Stdout    string `json:"stdout,omitempty"`
	Stderr    string `json:"stderr,omitempty"`
}

type RunList struct {
	Runs []Run `json:"runs"`
}

type SSHAccessResponse struct {
	Port int `json:"port"`
}

type SessionLogLine struct {
	Stream string    `json:"stream"`
	Text   string    `json:"text"`
	At     time.Time `json:"at"`
}

type SessionLogTail struct {
	SessionID string           `json:"sessionId"`
	Lines     []SessionLogLine `json:"lines"`
}

type GPUSample struct {
	Index       int `json:"index"`
	UtilPct     int `json:"utilPct"`
	MemUsedMiB  int `json:"memUsedMiB"`
	MemTotalMiB int `json:"memTotalMiB"`
}

type UsageSample struct {
	At           time.Time   `json:"at"`
	MemBytes     *int64      `json:"memBytes,omitempty"`
	CPUUsageUsec *int64      `json:"cpuUsageUsec,omitempty"`
	GPUs         []GPUSample `json:"gpus,omitempty"`
}

type SessionSeries struct {
	SessionID string        `json:"sessionId"`
	Samples   []UsageSample `json:"samples"`
}

type RunStats struct {
	Cores               int     `json:"cores,omitempty"`
	RequestedMemory     string  `json:"requestedMemory,omitempty"`
	ElapsedSeconds      int64   `json:"elapsedSeconds,omitempty"`
	MaxRSS              string  `json:"maxRss,omitempty"`
	CPUEfficiencyPct    float64 `json:"cpuEfficiencyPct,omitempty"`
	MemoryEfficiencyPct float64 `json:"memoryEfficiencyPct,omitempty"`
}

type Run struct {
	SessionID   string           `json:"sessionId"`
	Seq         int              `json:"seq"`
	Platform    string           `json:"platform,omitempty"`
	Alias       string           `json:"alias"`
	Account     string           `json:"account,omitempty"`
	Partition   string           `json:"partition"`
	RootFolder  string           `json:"rootFolder"`
	Resources   Resources        `json:"resources"`
	TunnelModes []string         `json:"tunnelModes"`
	FinalState  string           `json:"finalState"`
	Error       string           `json:"error,omitempty"`
	StartedAt   time.Time        `json:"startedAt,omitzero"`
	EndedAt     time.Time        `json:"endedAt"`
	Stats       *RunStats        `json:"stats,omitempty"`
	Samples     []UsageSample    `json:"samples,omitempty"`
	Logs        []SessionLogLine `json:"logs,omitempty"`
}
