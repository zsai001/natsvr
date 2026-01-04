package protocol

import (
	"encoding/binary"
	"errors"
	"io"
)

// Message types
type MessageType uint8

const (
	// Control messages
	MsgTypeAuth         MessageType = 1
	MsgTypeAuthResponse MessageType = 2
	MsgTypeHeartbeat    MessageType = 3
	MsgTypeHeartbeatAck MessageType = 4

	// Tunnel control
	MsgTypeConnect    MessageType = 10
	MsgTypeConnectAck MessageType = 11
	MsgTypeClose      MessageType = 12

	// Data transfer
	MsgTypeData MessageType = 20

	// UDP specific
	MsgTypeUDPData MessageType = 30

	// ICMP specific
	MsgTypeICMPData MessageType = 40

	// Local proxy control (agent-to-agent forwarding)
	MsgTypeLocalProxyStart MessageType = 50
	MsgTypeLocalProxyStop  MessageType = 51
	MsgTypeP2PConnect      MessageType = 52
	MsgTypeP2PConnectAck   MessageType = 53
	MsgTypeP2PData         MessageType = 54

	// Agent-to-Cloud forwarding (agent listens, cloud forwards to target)
	MsgTypeAgentCloudProxyStart MessageType = 60
	MsgTypeAgentCloudProxyStop  MessageType = 61
	MsgTypeAgentCloudConnect    MessageType = 62
	MsgTypeAgentCloudConnectAck MessageType = 63
	MsgTypeAgentCloudData       MessageType = 64

	// Rule-specific connection (per-rule isolation)
	MsgTypeRuleAuth         MessageType = 70 // Agent authenticates a rule-specific connection
	MsgTypeRuleAuthResponse MessageType = 71 // Cloud responds to rule auth

	// Error
	MsgTypeError MessageType = 255
)

// Protocol constants
const (
	MaxPayloadSize = 65535
	HeaderSize     = 9 // 1 (type) + 4 (tunnel ID) + 4 (payload length)
	MagicNumber    = 0x4E415453 // "NATS"
)

// Message represents a protocol message
type Message struct {
	Type     MessageType
	TunnelID uint32
	Payload  []byte
}

// AuthPayload is the authentication request payload
type AuthPayload struct {
	Token     string
	AgentName string
	AgentID   string
}

// AuthResponsePayload is the authentication response payload
type AuthResponsePayload struct {
	Success bool
	AgentID string
	Error   string
}

// ConnectPayload is the tunnel connect request payload
type ConnectPayload struct {
	Protocol   string // "tcp", "udp", "icmp"
	TargetHost string
	TargetPort uint16
	SourceHost string
	SourcePort uint16
}

// ConnectAckPayload is the tunnel connect response payload
type ConnectAckPayload struct {
	Success  bool
	TunnelID uint32
	Error    string
}

// UDPDataPayload contains UDP packet data with addressing info
type UDPDataPayload struct {
	SourceAddr string
	SourcePort uint16
	DestAddr   string
	DestPort   uint16
	Data       []byte
}

// ICMPDataPayload contains ICMP packet data
type ICMPDataPayload struct {
	Type     uint8
	Code     uint8
	DestAddr string
	Data     []byte
}

// ErrorPayload contains error information
type ErrorPayload struct {
	Code    uint16
	Message string
}

// LocalProxyStartPayload tells agent to start listening for local proxy
type LocalProxyStartPayload struct {
	RuleID        string
	Protocol      string
	ListenPort    uint16
	TargetAgentID string
	TargetHost    string
	TargetPort    uint16
}

// LocalProxyStopPayload tells agent to stop a local proxy
type LocalProxyStopPayload struct {
	RuleID string
}

// P2PConnectPayload is used for agent-to-agent tunnel connection
type P2PConnectPayload struct {
	SourceAgentID string
	Protocol      string
	TargetHost    string
	TargetPort    uint16
}

// P2PDataPayload wraps data between source and target agents
type P2PDataPayload struct {
	SourceAgentID string
	Data          []byte
}

// AgentCloudProxyStartPayload tells agent to start listening for agent-cloud proxy
type AgentCloudProxyStartPayload struct {
	RuleID     string
	Protocol   string
	ListenPort uint16
	TargetHost string
	TargetPort uint16
}

// AgentCloudProxyStopPayload tells agent to stop an agent-cloud proxy
type AgentCloudProxyStopPayload struct {
	RuleID string
}

// AgentCloudConnectPayload is used for agent-to-cloud tunnel connection
type AgentCloudConnectPayload struct {
	Protocol   string
	TargetHost string
	TargetPort uint16
}

// RuleAuthPayload is the rule-specific connection authentication payload
type RuleAuthPayload struct {
	Token   string // Agent auth token
	AgentID string // Agent ID (from main connection)
	RuleID  string // The rule this connection is dedicated to
}

// RuleAuthResponsePayload is the response to rule auth
type RuleAuthResponsePayload struct {
	Success bool
	RuleID  string
	Error   string
}

// Error codes
const (
	ErrCodeUnknown      uint16 = 0
	ErrCodeAuthFailed   uint16 = 1
	ErrCodeConnectFailed uint16 = 2
	ErrCodeTunnelClosed uint16 = 3
	ErrCodeInvalidMsg   uint16 = 4
)

var (
	ErrInvalidMessage  = errors.New("invalid message")
	ErrPayloadTooLarge = errors.New("payload too large")
	ErrInvalidMagic    = errors.New("invalid magic number")
)

// NewMessage creates a new message
func NewMessage(msgType MessageType, tunnelID uint32, payload []byte) *Message {
	return &Message{
		Type:     msgType,
		TunnelID: tunnelID,
		Payload:  payload,
	}
}

// NewAuthMessage creates an authentication message
func NewAuthMessage(token, agentName, agentID string) *Message {
	payload := EncodeAuthPayload(&AuthPayload{
		Token:     token,
		AgentName: agentName,
		AgentID:   agentID,
	})
	return NewMessage(MsgTypeAuth, 0, payload)
}

// NewHeartbeatMessage creates a heartbeat message
func NewHeartbeatMessage() *Message {
	return NewMessage(MsgTypeHeartbeat, 0, nil)
}

// NewHeartbeatAckMessage creates a heartbeat acknowledgment message
func NewHeartbeatAckMessage() *Message {
	return NewMessage(MsgTypeHeartbeatAck, 0, nil)
}

// NewConnectMessage creates a tunnel connect message
func NewConnectMessage(tunnelID uint32, protocol, targetHost string, targetPort uint16) *Message {
	payload := EncodeConnectPayload(&ConnectPayload{
		Protocol:   protocol,
		TargetHost: targetHost,
		TargetPort: targetPort,
	})
	return NewMessage(MsgTypeConnect, tunnelID, payload)
}

// NewDataMessage creates a data message
func NewDataMessage(tunnelID uint32, data []byte) *Message {
	return NewMessage(MsgTypeData, tunnelID, data)
}

// NewCloseMessage creates a tunnel close message
func NewCloseMessage(tunnelID uint32) *Message {
	return NewMessage(MsgTypeClose, tunnelID, nil)
}

// NewErrorMessage creates an error message
func NewErrorMessage(tunnelID uint32, code uint16, message string) *Message {
	payload := EncodeErrorPayload(&ErrorPayload{
		Code:    code,
		Message: message,
	})
	return NewMessage(MsgTypeError, tunnelID, payload)
}

// Encode serializes the message to bytes
func (m *Message) Encode() ([]byte, error) {
	if len(m.Payload) > MaxPayloadSize {
		return nil, ErrPayloadTooLarge
	}

	buf := make([]byte, HeaderSize+len(m.Payload))
	buf[0] = byte(m.Type)
	binary.BigEndian.PutUint32(buf[1:5], m.TunnelID)
	binary.BigEndian.PutUint32(buf[5:9], uint32(len(m.Payload)))
	copy(buf[9:], m.Payload)

	return buf, nil
}

// Decode deserializes bytes to a message
func Decode(r io.Reader) (*Message, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	msgType := MessageType(header[0])
	tunnelID := binary.BigEndian.Uint32(header[1:5])
	payloadLen := binary.BigEndian.Uint32(header[5:9])

	if payloadLen > MaxPayloadSize {
		return nil, ErrPayloadTooLarge
	}

	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
	}

	return &Message{
		Type:     msgType,
		TunnelID: tunnelID,
		Payload:  payload,
	}, nil
}

// DecodeFromBytes decodes a message from a byte slice
func DecodeFromBytes(data []byte) (*Message, error) {
	if len(data) < HeaderSize {
		return nil, ErrInvalidMessage
	}

	msgType := MessageType(data[0])
	tunnelID := binary.BigEndian.Uint32(data[1:5])
	payloadLen := binary.BigEndian.Uint32(data[5:9])

	if uint32(len(data)) < HeaderSize+payloadLen {
		return nil, ErrInvalidMessage
	}

	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		copy(payload, data[HeaderSize:HeaderSize+payloadLen])
	}

	return &Message{
		Type:     msgType,
		TunnelID: tunnelID,
		Payload:  payload,
	}, nil
}

// String returns a string representation of the message type
func (t MessageType) String() string {
	switch t {
	case MsgTypeAuth:
		return "Auth"
	case MsgTypeAuthResponse:
		return "AuthResponse"
	case MsgTypeHeartbeat:
		return "Heartbeat"
	case MsgTypeHeartbeatAck:
		return "HeartbeatAck"
	case MsgTypeConnect:
		return "Connect"
	case MsgTypeConnectAck:
		return "ConnectAck"
	case MsgTypeClose:
		return "Close"
	case MsgTypeData:
		return "Data"
	case MsgTypeUDPData:
		return "UDPData"
	case MsgTypeICMPData:
		return "ICMPData"
	case MsgTypeLocalProxyStart:
		return "LocalProxyStart"
	case MsgTypeLocalProxyStop:
		return "LocalProxyStop"
	case MsgTypeP2PConnect:
		return "P2PConnect"
	case MsgTypeP2PConnectAck:
		return "P2PConnectAck"
	case MsgTypeP2PData:
		return "P2PData"
	case MsgTypeAgentCloudProxyStart:
		return "AgentCloudProxyStart"
	case MsgTypeAgentCloudProxyStop:
		return "AgentCloudProxyStop"
	case MsgTypeAgentCloudConnect:
		return "AgentCloudConnect"
	case MsgTypeAgentCloudConnectAck:
		return "AgentCloudConnectAck"
	case MsgTypeAgentCloudData:
		return "AgentCloudData"
	case MsgTypeRuleAuth:
		return "RuleAuth"
	case MsgTypeRuleAuthResponse:
		return "RuleAuthResponse"
	case MsgTypeError:
		return "Error"
	default:
		return "Unknown"
	}
}

