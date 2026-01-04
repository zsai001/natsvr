package cloud

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/natsvr/natsvr/internal/protocol"
)

// WebFS is set by main package to embed frontend files
var WebFS embed.FS

// Config holds server configuration
type Config struct {
	Addr    string
	Token   string
	DBPath  string
	DevMode bool   // When true, proxy frontend to Vite dev server
	DevURL  string // Vite dev server URL (default: http://localhost:5173)
}

// Server is the main cloud server
type Server struct {
	config     *Config
	store      *Store
	agents     map[string]*AgentConn
	agentsMu   sync.RWMutex
	forwarder  *Forwarder
	router     *gin.Engine
	httpServer *http.Server
	upgrader   websocket.Upgrader
	ctx        context.Context
	cancel     context.CancelFunc
}

// AgentConn represents a connected agent
type AgentConn struct {
	ID            string
	Name          string
	IP            string
	Conn          *websocket.Conn // Main control connection
	ConnectedAt   time.Time
	LastHeartbeat time.Time
	TxBytes       int64
	RxBytes       int64
	ActiveTunnels int
	writeMu       sync.Mutex
	tunnels       map[uint32]*Tunnel
	tunnelsMu     sync.RWMutex
	// Rule-specific connections (per-rule isolation)
	ruleConns   map[string]*RuleConn // ruleID -> connection
	ruleConnsMu sync.RWMutex
}

// RuleConn represents a rule-specific WebSocket connection
type RuleConn struct {
	RuleID  string
	Conn    *websocket.Conn
	writeMu sync.Mutex
}

// Tunnel represents an active tunnel
type Tunnel struct {
	ID         uint32
	Protocol   string
	TargetHost string
	TargetPort uint16
	SourceHost string
	SourcePort uint16
	CreatedAt  time.Time
	BytesSent  int64
	BytesRecv  int64
}

// NewServer creates a new cloud server
func NewServer(cfg *Config) (*Server, error) {
	store, err := NewStore(cfg.DBPath)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		config: cfg,
		store:  store,
		agents: make(map[string]*AgentConn),
		ctx:    ctx,
		cancel: cancel,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
			ReadBufferSize:  65536,
			WriteBufferSize: 65536,
		},
	}

	s.forwarder = NewForwarder(s)
	s.setupRouter()

	return s, nil
}

func (s *Server) setupRouter() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	// WebSocket endpoint
	r.GET("/ws", s.handleWebSocket)

	// API endpoints
	api := r.Group("/api")
	{
		api.GET("/version", s.handleGetVersion)
		api.GET("/stats", s.handleGetStats)

		api.GET("/agents", s.handleGetAgents)
		api.GET("/agents/:id", s.handleGetAgent)

		api.GET("/forward-rules", s.handleGetForwardRules)
		api.POST("/forward-rules", s.handleCreateForwardRule)
		api.PATCH("/forward-rules/:id", s.handleUpdateForwardRule)
		api.DELETE("/forward-rules/:id", s.handleDeleteForwardRule)

		api.GET("/tokens", s.handleGetTokens)
		api.POST("/tokens", s.handleCreateToken)
		api.DELETE("/tokens/:id", s.handleDeleteToken)
	}

	// Serve frontend
	if s.config.DevMode {
		// Development mode: proxy to Vite dev server
		devURL := s.config.DevURL
		if devURL == "" {
			devURL = "http://localhost:5173"
		}
		target, err := url.Parse(devURL)
		if err != nil {
			log.Fatalf("Invalid dev server URL: %v", err)
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		log.Printf("Dev mode: proxying frontend to %s", devURL)

		r.GET("/", func(c *gin.Context) {
			proxy.ServeHTTP(c.Writer, c.Request)
		})
		r.NoRoute(func(c *gin.Context) {
			proxy.ServeHTTP(c.Writer, c.Request)
		})
	} else {
		// Production mode: serve embedded frontend
		distFS, err := fs.Sub(WebFS, "dist")
		if err != nil {
			log.Printf("Warning: Could not load embedded frontend: %v, trying filesystem fallback", err)
			// Fallback: serve from filesystem for development
			r.Static("/assets", "./web/dist/assets")
			r.StaticFile("/", "./web/dist/index.html")
			r.NoRoute(func(c *gin.Context) {
				c.File("./web/dist/index.html")
			})
		} else {
			// Create sub-filesystem for assets folder
			assetsFS, err := fs.Sub(distFS, "assets")
			if err != nil {
				log.Printf("Warning: Could not load assets: %v", err)
			} else {
				r.StaticFS("/assets", http.FS(assetsFS))
			}
			r.GET("/", func(c *gin.Context) {
				data, _ := fs.ReadFile(distFS, "index.html")
				c.Data(http.StatusOK, "text/html; charset=utf-8", data)
			})
			r.NoRoute(func(c *gin.Context) {
				data, _ := fs.ReadFile(distFS, "index.html")
				c.Data(http.StatusOK, "text/html; charset=utf-8", data)
			})
		}
	}

	s.router = r
}

// Run starts the server
func (s *Server) Run() error {
	// Start forwarder
	go s.forwarder.Run()

	// Start heartbeat checker
	go s.heartbeatChecker()

	s.httpServer = &http.Server{
		Addr:    s.config.Addr,
		Handler: s.router,
	}

	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown() {
	s.cancel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if s.httpServer != nil {
		s.httpServer.Shutdown(ctx)
	}

	s.agentsMu.Lock()
	for _, agent := range s.agents {
		agent.Conn.Close()
	}
	s.agentsMu.Unlock()

	s.store.Close()
}

func (s *Server) handleWebSocket(c *gin.Context) {
	conn, err := s.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	clientIP := c.ClientIP()
	log.Printf("New WebSocket connection from %s", clientIP)

	go s.handleAgentConnection(conn, clientIP)
}

func (s *Server) handleAgentConnection(conn *websocket.Conn, clientIP string) {
	defer conn.Close()

	// Wait for authentication
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	_, data, err := conn.ReadMessage()
	if err != nil {
		log.Printf("Failed to read auth message: %v", err)
		return
	}

	msg, err := protocol.DecodeFromBytes(data)
	if err != nil {
		log.Printf("Failed to decode auth message: %v", err)
		return
	}

	// Check if this is a rule-specific connection
	if msg.Type == protocol.MsgTypeRuleAuth {
		s.handleRuleConnection(conn, clientIP, msg)
		return
	}

	if msg.Type != protocol.MsgTypeAuth {
		log.Printf("Expected auth message, got %v", msg.Type)
		return
	}

	authPayload, err := protocol.DecodeAuthPayload(msg.Payload)
	if err != nil {
		log.Printf("Failed to decode auth payload: %v", err)
		return
	}

	// Validate token
	valid := s.validateToken(authPayload.Token)
	if !valid {
		log.Printf("Invalid token from %s", clientIP)
		s.sendAuthResponse(conn, false, "", "Invalid token")
		return
	}

	// Create agent connection
	agentID := authPayload.AgentID
	if agentID == "" {
		agentID = generateAgentID()
	}

	agent := &AgentConn{
		ID:            agentID,
		Name:          authPayload.AgentName,
		IP:            clientIP,
		Conn:          conn,
		ConnectedAt:   time.Now(),
		LastHeartbeat: time.Now(),
		tunnels:       make(map[uint32]*Tunnel),
		ruleConns:     make(map[string]*RuleConn),
	}

	s.agentsMu.Lock()
	// Check for existing agent with same ID
	if existing, ok := s.agents[agentID]; ok {
		existing.Conn.Close()
		delete(s.agents, agentID)
	}
	s.agents[agentID] = agent
	s.agentsMu.Unlock()

	log.Printf("Agent '%s' (%s) connected from %s", agent.Name, agent.ID, clientIP)

	// Send auth response
	s.sendAuthResponse(conn, true, agentID, "")

	// Reset read deadline
	conn.SetReadDeadline(time.Time{})

	// Notify forwarder about new agent connection
	s.forwarder.OnAgentConnected(agent)

	// Handle messages
	s.handleAgentMessages(agent)

	// Cleanup on disconnect
	s.agentsMu.Lock()
	delete(s.agents, agentID)
	s.agentsMu.Unlock()

	log.Printf("Agent '%s' (%s) disconnected", agent.Name, agent.ID)
}

func (s *Server) validateToken(token string) bool {
	// Check against config token
	if token == s.config.Token {
		return true
	}

	// Check against stored tokens
	tokens, _ := s.store.GetTokens()
	for _, t := range tokens {
		if t.Token == token {
			s.store.IncrementTokenUsage(t.ID)
			return true
		}
	}

	return false
}

func (s *Server) sendAuthResponse(conn *websocket.Conn, success bool, agentID, errMsg string) {
	payload := protocol.EncodeAuthResponsePayload(&protocol.AuthResponsePayload{
		Success: success,
		AgentID: agentID,
		Error:   errMsg,
	})
	msg := protocol.NewMessage(protocol.MsgTypeAuthResponse, 0, payload)
	data, _ := msg.Encode()
	conn.WriteMessage(websocket.BinaryMessage, data)
}

func (s *Server) handleAgentMessages(agent *AgentConn) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Panic in handleAgentMessages for agent %s: %v", agent.ID, r)
		}
	}()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		_, data, err := agent.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("Agent %s read error: %v", agent.ID, err)
			}
			return
		}

		agent.RxBytes += int64(len(data))

		msg, err := protocol.DecodeFromBytes(data)
		if err != nil {
			log.Printf("Failed to decode message from agent %s: %v", agent.ID, err)
			continue
		}

		switch msg.Type {
		case protocol.MsgTypeHeartbeat:
			agent.LastHeartbeat = time.Now()
			s.sendToAgent(agent, protocol.NewHeartbeatAckMessage())

		case protocol.MsgTypeData:
			s.forwarder.HandleData(agent, msg)

		case protocol.MsgTypeUDPData:
			s.forwarder.HandleUDPData(agent, msg)

		case protocol.MsgTypeICMPData:
			s.forwarder.HandleICMPData(agent, msg)

		case protocol.MsgTypeConnectAck:
			s.forwarder.HandleConnectAck(agent, msg)

		case protocol.MsgTypeClose:
			s.forwarder.HandleClose(agent, msg)

		case protocol.MsgTypeP2PConnect:
			go s.forwarder.HandleP2PConnect(agent, msg)

		case protocol.MsgTypeP2PData:
			log.Printf("Received P2P data from agent %s, tunnelID=%d, size=%d bytes", agent.ID, msg.TunnelID, len(msg.Payload))
			s.forwarder.HandleP2PData(agent, msg)

		case protocol.MsgTypeAgentCloudConnect:
			go s.forwarder.HandleAgentCloudConnect(agent, msg)

		case protocol.MsgTypeAgentCloudData:
			s.forwarder.HandleAgentCloudData(agent, msg)
		}
	}
}

func (s *Server) sendToAgent(agent *AgentConn, msg *protocol.Message) error {
	if agent == nil {
		return fmt.Errorf("agent is nil")
	}

	data, err := msg.Encode()
	if err != nil {
		return err
	}

	agent.writeMu.Lock()
	defer agent.writeMu.Unlock()

	if agent.Conn == nil {
		return fmt.Errorf("agent connection is nil")
	}

	err = agent.Conn.WriteMessage(websocket.BinaryMessage, data)
	if err == nil {
		agent.TxBytes += int64(len(data))
	}
	return err
}

// sendToAgentRule sends a message to an agent's rule-specific connection
// Falls back to main connection if rule connection doesn't exist
func (s *Server) sendToAgentRule(agent *AgentConn, ruleID string, msg *protocol.Message) error {
	if agent == nil {
		return fmt.Errorf("agent is nil")
	}

	// Try rule-specific connection first
	agent.ruleConnsMu.RLock()
	ruleConn, hasRuleConn := agent.ruleConns[ruleID]
	agent.ruleConnsMu.RUnlock()

	if hasRuleConn && ruleConn != nil && ruleConn.Conn != nil {
		data, err := msg.Encode()
		if err != nil {
			return err
		}

		ruleConn.writeMu.Lock()
		err = ruleConn.Conn.WriteMessage(websocket.BinaryMessage, data)
		ruleConn.writeMu.Unlock()

		if err == nil {
			agent.TxBytes += int64(len(data))
			return nil
		}
		// If rule connection fails, fall through to main connection
		log.Printf("Rule connection %s failed, falling back to main: %v", ruleID, err)
	}

	// Fall back to main connection
	return s.sendToAgent(agent, msg)
}

// GetAgentRuleConn gets an agent's rule-specific connection
func (s *Server) GetAgentRuleConn(agentID, ruleID string) *RuleConn {
	agent := s.GetAgent(agentID)
	if agent == nil {
		return nil
	}

	agent.ruleConnsMu.RLock()
	defer agent.ruleConnsMu.RUnlock()
	return agent.ruleConns[ruleID]
}

func (s *Server) GetAgent(id string) *AgentConn {
	s.agentsMu.RLock()
	defer s.agentsMu.RUnlock()
	return s.agents[id]
}

func (s *Server) GetAgentByName(name string) *AgentConn {
	s.agentsMu.RLock()
	defer s.agentsMu.RUnlock()
	for _, agent := range s.agents {
		if agent.Name == name {
			return agent
		}
	}
	return nil
}

func (s *Server) GetAgents() []*AgentConn {
	s.agentsMu.RLock()
	defer s.agentsMu.RUnlock()

	agents := make([]*AgentConn, 0, len(s.agents))
	for _, a := range s.agents {
		agents = append(agents, a)
	}
	return agents
}

func (s *Server) heartbeatChecker() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.agentsMu.RLock()
			for _, agent := range s.agents {
				if time.Since(agent.LastHeartbeat) > 90*time.Second {
					log.Printf("Agent %s heartbeat timeout", agent.ID)
					agent.Conn.Close()
				}
			}
			s.agentsMu.RUnlock()
		}
	}
}

// handleRuleConnection handles a rule-specific WebSocket connection
func (s *Server) handleRuleConnection(conn *websocket.Conn, clientIP string, authMsg *protocol.Message) {
	ruleAuth, err := protocol.DecodeRuleAuthPayload(authMsg.Payload)
	if err != nil {
		log.Printf("Failed to decode rule auth payload: %v", err)
		s.sendRuleAuthResponse(conn, false, "", "Invalid payload")
		return
	}

	// Validate token
	if !s.validateToken(ruleAuth.Token) {
		log.Printf("Invalid token for rule connection from %s", clientIP)
		s.sendRuleAuthResponse(conn, false, ruleAuth.RuleID, "Invalid token")
		return
	}

	// Find the agent
	agent := s.GetAgent(ruleAuth.AgentID)
	if agent == nil {
		log.Printf("Agent %s not found for rule connection", ruleAuth.AgentID)
		s.sendRuleAuthResponse(conn, false, ruleAuth.RuleID, "Agent not found")
		return
	}

	// Register rule connection
	ruleConn := &RuleConn{
		RuleID: ruleAuth.RuleID,
		Conn:   conn,
	}

	agent.ruleConnsMu.Lock()
	// Close existing rule connection if any
	if existing, ok := agent.ruleConns[ruleAuth.RuleID]; ok {
		existing.Conn.Close()
	}
	agent.ruleConns[ruleAuth.RuleID] = ruleConn
	agent.ruleConnsMu.Unlock()

	log.Printf("Rule connection established: agent=%s, rule=%s from %s", agent.Name, ruleAuth.RuleID, clientIP)

	// Send success response
	s.sendRuleAuthResponse(conn, true, ruleAuth.RuleID, "")

	// Reset read deadline
	conn.SetReadDeadline(time.Time{})

	// Handle messages on this rule connection
	s.handleRuleMessages(agent, ruleConn)

	// Cleanup on disconnect
	agent.ruleConnsMu.Lock()
	delete(agent.ruleConns, ruleAuth.RuleID)
	agent.ruleConnsMu.Unlock()

	log.Printf("Rule connection closed: agent=%s, rule=%s", agent.Name, ruleAuth.RuleID)
}

func (s *Server) sendRuleAuthResponse(conn *websocket.Conn, success bool, ruleID, errMsg string) {
	payload := protocol.EncodeRuleAuthResponsePayload(&protocol.RuleAuthResponsePayload{
		Success: success,
		RuleID:  ruleID,
		Error:   errMsg,
	})
	msg := protocol.NewMessage(protocol.MsgTypeRuleAuthResponse, 0, payload)
	data, _ := msg.Encode()
	conn.WriteMessage(websocket.BinaryMessage, data)
}

// handleRuleMessages handles messages on a rule-specific connection
func (s *Server) handleRuleMessages(agent *AgentConn, ruleConn *RuleConn) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Panic in handleRuleMessages for agent %s rule %s: %v", agent.ID, ruleConn.RuleID, r)
		}
	}()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		_, data, err := ruleConn.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("Agent %s rule %s read error: %v", agent.ID, ruleConn.RuleID, err)
			}
			return
		}

		agent.RxBytes += int64(len(data))

		msg, err := protocol.DecodeFromBytes(data)
		if err != nil {
			log.Printf("Failed to decode message from agent %s rule %s: %v", agent.ID, ruleConn.RuleID, err)
			continue
		}

		// Handle messages same as main connection, but they are isolated to this rule
		switch msg.Type {
		case protocol.MsgTypeHeartbeat:
			agent.LastHeartbeat = time.Now()
			s.sendToRuleConn(ruleConn, protocol.NewHeartbeatAckMessage())

		case protocol.MsgTypeData:
			s.forwarder.HandleData(agent, msg)

		case protocol.MsgTypeUDPData:
			s.forwarder.HandleUDPData(agent, msg)

		case protocol.MsgTypeConnectAck:
			s.forwarder.HandleConnectAck(agent, msg)

		case protocol.MsgTypeClose:
			s.forwarder.HandleClose(agent, msg)

		case protocol.MsgTypeP2PConnect:
			go s.forwarder.HandleP2PConnect(agent, msg)

		case protocol.MsgTypeP2PData:
			s.forwarder.HandleP2PData(agent, msg)

		case protocol.MsgTypeAgentCloudConnect:
			go s.forwarder.HandleAgentCloudConnect(agent, msg)

		case protocol.MsgTypeAgentCloudData:
			s.forwarder.HandleAgentCloudData(agent, msg)
		}
	}
}

func (s *Server) sendToRuleConn(ruleConn *RuleConn, msg *protocol.Message) error {
	if ruleConn == nil || ruleConn.Conn == nil {
		return fmt.Errorf("rule connection is nil")
	}

	data, err := msg.Encode()
	if err != nil {
		return err
	}

	ruleConn.writeMu.Lock()
	defer ruleConn.writeMu.Unlock()

	return ruleConn.Conn.WriteMessage(websocket.BinaryMessage, data)
}

func generateAgentID() string {
	return time.Now().Format("20060102150405") + "-" + randomString(8)
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
		time.Sleep(time.Nanosecond)
	}
	return string(b)
}
