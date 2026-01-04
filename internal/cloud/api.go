package cloud

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/natsvr/natsvr/pkg/version"
)

// API response types
type AgentResponse struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	IP            string `json:"ip"`
	Online        bool   `json:"online"`
	LastSeen      string `json:"lastSeen"`
	ActiveTunnels int    `json:"activeTunnels"`
	TxBytes       int64  `json:"txBytes"`
	RxBytes       int64  `json:"rxBytes"`
}

type ForwardRuleResponse struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	Protocol      string `json:"protocol"`
	SourceAgentID string `json:"sourceAgentId,omitempty"`
	ListenPort    int    `json:"listenPort"`
	TargetAgentID string `json:"targetAgentId,omitempty"`
	TargetHost    string `json:"targetHost"`
	TargetPort    int    `json:"targetPort"`
	Enabled       bool   `json:"enabled"`
	RateLimit     int64  `json:"rateLimit"`
	TrafficLimit  int64  `json:"trafficLimit"`
	TrafficUsed   int64  `json:"trafficUsed"`
	CreatedAt     string `json:"createdAt"`
}

type StatsResponse struct {
	TxBytes     int64   `json:"txBytes"`
	RxBytes     int64   `json:"rxBytes"`
	TxSpeed     float64 `json:"txSpeed"`
	RxSpeed     float64 `json:"rxSpeed"`
	OnlineCount int     `json:"onlineCount"`
	TotalRules  int     `json:"totalRules"`
}

type TokenResponse struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Token      string `json:"token"`
	UsageCount int    `json:"usageCount"`
	CreatedAt  string `json:"createdAt"`
}

// Agent endpoints
func (s *Server) handleGetAgents(c *gin.Context) {
	s.agentsMu.RLock()
	defer s.agentsMu.RUnlock()

	agents := make([]AgentResponse, 0, len(s.agents))
	for _, a := range s.agents {
		agents = append(agents, AgentResponse{
			ID:            a.ID,
			Name:          a.Name,
			IP:            a.IP,
			Online:        true,
			LastSeen:      a.LastHeartbeat.Format("2006-01-02T15:04:05Z"),
			ActiveTunnels: a.ActiveTunnels,
			TxBytes:       a.TxBytes,
			RxBytes:       a.RxBytes,
		})
	}

	c.JSON(http.StatusOK, agents)
}

func (s *Server) handleGetAgent(c *gin.Context) {
	id := c.Param("id")

	s.agentsMu.RLock()
	agent, exists := s.agents[id]
	s.agentsMu.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
		return
	}

	c.JSON(http.StatusOK, AgentResponse{
		ID:            agent.ID,
		Name:          agent.Name,
		IP:            agent.IP,
		Online:        true,
		LastSeen:      agent.LastHeartbeat.Format("2006-01-02T15:04:05Z"),
		ActiveTunnels: agent.ActiveTunnels,
		TxBytes:       agent.TxBytes,
		RxBytes:       agent.RxBytes,
	})
}

// Forward rule endpoints
func (s *Server) handleGetForwardRules(c *gin.Context) {
	rules, err := s.store.GetForwardRules()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	responses := make([]ForwardRuleResponse, len(rules))
	for i, r := range rules {
		// Get real-time traffic if rule is active
		trafficUsed := r.TrafficUsed
		if liveTraffic := s.forwarder.GetRuleTraffic(r.ID); liveTraffic > 0 {
			trafficUsed = liveTraffic
		}
		
		responses[i] = ForwardRuleResponse{
			ID:            r.ID,
			Name:          r.Name,
			Type:          r.Type,
			Protocol:      r.Protocol,
			SourceAgentID: r.SourceAgentID,
			ListenPort:    r.ListenPort,
			TargetAgentID: r.TargetAgentID,
			TargetHost:    r.TargetHost,
			TargetPort:    r.TargetPort,
			Enabled:       r.Enabled,
			RateLimit:     r.RateLimit,
			TrafficLimit:  r.TrafficLimit,
			TrafficUsed:   trafficUsed,
			CreatedAt:     r.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}
	}

	c.JSON(http.StatusOK, responses)
}

type CreateForwardRuleRequest struct {
	Name          string `json:"name" binding:"required"`
	Type          string `json:"type" binding:"required"`
	Protocol      string `json:"protocol" binding:"required"`
	SourceAgentID string `json:"sourceAgentId"`
	ListenPort    int    `json:"listenPort" binding:"required"`
	TargetAgentID string `json:"targetAgentId"`
	TargetHost    string `json:"targetHost" binding:"required"`
	TargetPort    int    `json:"targetPort" binding:"required"`
	RateLimit     int64  `json:"rateLimit"`     // bytes per second, 0 = unlimited
	TrafficLimit  int64  `json:"trafficLimit"`  // max total bytes, 0 = unlimited
}

func (s *Server) handleCreateForwardRule(c *gin.Context) {
	var req CreateForwardRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate targetAgentId is required for cloud-agent and agent-agent types
	if (req.Type == "cloud-agent" || req.Type == "remote" || req.Type == "agent-agent" || req.Type == "local" || req.Type == "p2p") && req.TargetAgentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "targetAgentId is required for this forward type"})
		return
	}

	// Validate sourceAgentId is required for agent-cloud and agent-agent types
	if (req.Type == "agent-cloud" || req.Type == "agent-agent" || req.Type == "local" || req.Type == "p2p") && req.SourceAgentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "sourceAgentId is required for this forward type"})
		return
	}

	rule := &ForwardRule{
		ID:            uuid.New().String(),
		Name:          req.Name,
		Type:          req.Type,
		Protocol:      req.Protocol,
		SourceAgentID: req.SourceAgentID,
		ListenPort:    req.ListenPort,
		TargetAgentID: req.TargetAgentID,
		TargetHost:    req.TargetHost,
		TargetPort:    req.TargetPort,
		Enabled:       true,
		RateLimit:     req.RateLimit,
		TrafficLimit:  req.TrafficLimit,
	}

	if err := s.store.CreateForwardRule(rule); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Start the rule
	if err := s.forwarder.StartRule(rule); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, ForwardRuleResponse{
		ID:            rule.ID,
		Name:          rule.Name,
		Type:          rule.Type,
		Protocol:      rule.Protocol,
		SourceAgentID: rule.SourceAgentID,
		ListenPort:    rule.ListenPort,
		TargetAgentID: rule.TargetAgentID,
		TargetHost:    rule.TargetHost,
		TargetPort:    rule.TargetPort,
		Enabled:       rule.Enabled,
		RateLimit:     rule.RateLimit,
		TrafficLimit:  rule.TrafficLimit,
		TrafficUsed:   rule.TrafficUsed,
		CreatedAt:     rule.CreatedAt.Format("2006-01-02T15:04:05Z"),
	})
}

type UpdateForwardRuleRequest struct {
	Enabled *bool `json:"enabled"`
}

func (s *Server) handleUpdateForwardRule(c *gin.Context) {
	id := c.Param("id")

	var req UpdateForwardRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rule, err := s.store.GetForwardRule(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
		return
	}

	if req.Enabled != nil {
		if *req.Enabled && !rule.Enabled {
			// Enable rule
			if err := s.forwarder.StartRule(rule); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		} else if !*req.Enabled && rule.Enabled {
			// Disable rule
			s.forwarder.StopRule(id)
		}
		rule.Enabled = *req.Enabled
	}

	if err := s.store.UpdateForwardRule(rule); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, ForwardRuleResponse{
		ID:            rule.ID,
		Name:          rule.Name,
		Type:          rule.Type,
		Protocol:      rule.Protocol,
		SourceAgentID: rule.SourceAgentID,
		ListenPort:    rule.ListenPort,
		TargetAgentID: rule.TargetAgentID,
		TargetHost:    rule.TargetHost,
		TargetPort:    rule.TargetPort,
		Enabled:       rule.Enabled,
		RateLimit:     rule.RateLimit,
		TrafficLimit:  rule.TrafficLimit,
		TrafficUsed:   rule.TrafficUsed,
		CreatedAt:     rule.CreatedAt.Format("2006-01-02T15:04:05Z"),
	})
}

// Stats endpoint
func (s *Server) handleGetStats(c *gin.Context) {
	txBytes, rxBytes, txSpeed, rxSpeed := s.forwarder.GetGlobalStats()
	
	s.agentsMu.RLock()
	onlineCount := len(s.agents)
	s.agentsMu.RUnlock()
	
	rules, _ := s.store.GetForwardRules()
	totalRules := len(rules)
	
	c.JSON(http.StatusOK, StatsResponse{
		TxBytes:     txBytes,
		RxBytes:     rxBytes,
		TxSpeed:     txSpeed,
		RxSpeed:     rxSpeed,
		OnlineCount: onlineCount,
		TotalRules:  totalRules,
	})
}

func (s *Server) handleDeleteForwardRule(c *gin.Context) {
	id := c.Param("id")

	// Stop the rule first
	s.forwarder.StopRule(id)

	if err := s.store.DeleteForwardRule(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rule deleted"})
}

// Token endpoints
func (s *Server) handleGetTokens(c *gin.Context) {
	tokens, err := s.store.GetTokens()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	responses := make([]TokenResponse, len(tokens))
	for i, t := range tokens {
		responses[i] = TokenResponse{
			ID:         t.ID,
			Name:       t.Name,
			Token:      t.Token,
			UsageCount: t.UsageCount,
			CreatedAt:  t.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}
	}

	c.JSON(http.StatusOK, responses)
}

type CreateTokenRequest struct {
	Name string `json:"name" binding:"required"`
}

func (s *Server) handleCreateToken(c *gin.Context) {
	var req CreateTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	token := &Token{
		ID:    uuid.New().String(),
		Name:  req.Name,
		Token: uuid.New().String() + "-" + uuid.New().String(),
	}

	if err := s.store.CreateToken(token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, TokenResponse{
		ID:         token.ID,
		Name:       token.Name,
		Token:      token.Token,
		UsageCount: token.UsageCount,
		CreatedAt:  token.CreatedAt.Format("2006-01-02T15:04:05Z"),
	})
}

func (s *Server) handleDeleteToken(c *gin.Context) {
	id := c.Param("id")

	if err := s.store.DeleteToken(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Token deleted"})
}

// Version endpoint
func (s *Server) handleGetVersion(c *gin.Context) {
	c.JSON(http.StatusOK, version.Get())
}

