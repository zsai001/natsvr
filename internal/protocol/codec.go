package protocol

import (
	"encoding/binary"
	"errors"
)

var ErrInvalidPayload = errors.New("invalid payload")

// EncodeAuthPayload encodes an authentication payload
func EncodeAuthPayload(p *AuthPayload) []byte {
	tokenBytes := []byte(p.Token)
	nameBytes := []byte(p.AgentName)
	idBytes := []byte(p.AgentID)

	buf := make([]byte, 6+len(tokenBytes)+len(nameBytes)+len(idBytes))

	binary.BigEndian.PutUint16(buf[0:2], uint16(len(tokenBytes)))
	copy(buf[2:2+len(tokenBytes)], tokenBytes)

	offset := 2 + len(tokenBytes)
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(nameBytes)))
	copy(buf[offset+2:offset+2+len(nameBytes)], nameBytes)

	offset = offset + 2 + len(nameBytes)
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(idBytes)))
	copy(buf[offset+2:], idBytes)

	return buf
}

// DecodeAuthPayload decodes an authentication payload
func DecodeAuthPayload(data []byte) (*AuthPayload, error) {
	if len(data) < 6 {
		return nil, ErrInvalidPayload
	}

	offset := 0

	tokenLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if offset+int(tokenLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	token := string(data[offset : offset+int(tokenLen)])
	offset += int(tokenLen)

	if offset+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	nameLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if offset+int(nameLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	name := string(data[offset : offset+int(nameLen)])
	offset += int(nameLen)

	if offset+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	idLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if offset+int(idLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	id := string(data[offset : offset+int(idLen)])

	return &AuthPayload{
		Token:     token,
		AgentName: name,
		AgentID:   id,
	}, nil
}

// EncodeAuthResponsePayload encodes an authentication response payload
func EncodeAuthResponsePayload(p *AuthResponsePayload) []byte {
	idBytes := []byte(p.AgentID)
	errBytes := []byte(p.Error)

	buf := make([]byte, 5+len(idBytes)+len(errBytes))

	if p.Success {
		buf[0] = 1
	} else {
		buf[0] = 0
	}

	binary.BigEndian.PutUint16(buf[1:3], uint16(len(idBytes)))
	copy(buf[3:3+len(idBytes)], idBytes)

	offset := 3 + len(idBytes)
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(errBytes)))
	copy(buf[offset+2:], errBytes)

	return buf
}

// DecodeAuthResponsePayload decodes an authentication response payload
func DecodeAuthResponsePayload(data []byte) (*AuthResponsePayload, error) {
	if len(data) < 5 {
		return nil, ErrInvalidPayload
	}

	success := data[0] == 1

	idLen := binary.BigEndian.Uint16(data[1:3])
	if 3+int(idLen)+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	id := string(data[3 : 3+idLen])

	offset := 3 + int(idLen)
	errLen := binary.BigEndian.Uint16(data[offset : offset+2])
	if offset+2+int(errLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	errMsg := string(data[offset+2 : offset+2+int(errLen)])

	return &AuthResponsePayload{
		Success: success,
		AgentID: id,
		Error:   errMsg,
	}, nil
}

// EncodeConnectPayload encodes a connect payload
func EncodeConnectPayload(p *ConnectPayload) []byte {
	protocolBytes := []byte(p.Protocol)
	hostBytes := []byte(p.TargetHost)
	srcHostBytes := []byte(p.SourceHost)

	buf := make([]byte, 10+len(protocolBytes)+len(hostBytes)+len(srcHostBytes))

	offset := 0
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(protocolBytes)))
	offset += 2
	copy(buf[offset:offset+len(protocolBytes)], protocolBytes)
	offset += len(protocolBytes)

	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(hostBytes)))
	offset += 2
	copy(buf[offset:offset+len(hostBytes)], hostBytes)
	offset += len(hostBytes)

	binary.BigEndian.PutUint16(buf[offset:offset+2], p.TargetPort)
	offset += 2

	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(srcHostBytes)))
	offset += 2
	copy(buf[offset:offset+len(srcHostBytes)], srcHostBytes)
	offset += len(srcHostBytes)

	binary.BigEndian.PutUint16(buf[offset:offset+2], p.SourcePort)

	return buf
}

// DecodeConnectPayload decodes a connect payload
func DecodeConnectPayload(data []byte) (*ConnectPayload, error) {
	if len(data) < 10 {
		return nil, ErrInvalidPayload
	}

	offset := 0

	protocolLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if offset+int(protocolLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	protocol := string(data[offset : offset+int(protocolLen)])
	offset += int(protocolLen)

	if offset+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	hostLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if offset+int(hostLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	host := string(data[offset : offset+int(hostLen)])
	offset += int(hostLen)

	if offset+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	port := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	var srcHost string
	var srcPort uint16

	if offset+2 <= len(data) {
		srcHostLen := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		if offset+int(srcHostLen) <= len(data) {
			srcHost = string(data[offset : offset+int(srcHostLen)])
			offset += int(srcHostLen)
		}
		if offset+2 <= len(data) {
			srcPort = binary.BigEndian.Uint16(data[offset : offset+2])
		}
	}

	return &ConnectPayload{
		Protocol:   protocol,
		TargetHost: host,
		TargetPort: port,
		SourceHost: srcHost,
		SourcePort: srcPort,
	}, nil
}

// EncodeConnectAckPayload encodes a connect acknowledgment payload
func EncodeConnectAckPayload(p *ConnectAckPayload) []byte {
	errBytes := []byte(p.Error)
	buf := make([]byte, 7+len(errBytes))

	if p.Success {
		buf[0] = 1
	} else {
		buf[0] = 0
	}

	binary.BigEndian.PutUint32(buf[1:5], p.TunnelID)
	binary.BigEndian.PutUint16(buf[5:7], uint16(len(errBytes)))
	copy(buf[7:], errBytes)

	return buf
}

// DecodeConnectAckPayload decodes a connect acknowledgment payload
func DecodeConnectAckPayload(data []byte) (*ConnectAckPayload, error) {
	if len(data) < 7 {
		return nil, ErrInvalidPayload
	}

	success := data[0] == 1
	tunnelID := binary.BigEndian.Uint32(data[1:5])
	errLen := binary.BigEndian.Uint16(data[5:7])

	if 7+int(errLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	errMsg := string(data[7 : 7+errLen])

	return &ConnectAckPayload{
		Success:  success,
		TunnelID: tunnelID,
		Error:    errMsg,
	}, nil
}

// EncodeUDPDataPayload encodes a UDP data payload
func EncodeUDPDataPayload(p *UDPDataPayload) []byte {
	srcAddrBytes := []byte(p.SourceAddr)
	destAddrBytes := []byte(p.DestAddr)

	buf := make([]byte, 8+len(srcAddrBytes)+len(destAddrBytes)+len(p.Data))

	offset := 0
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(srcAddrBytes)))
	offset += 2
	copy(buf[offset:offset+len(srcAddrBytes)], srcAddrBytes)
	offset += len(srcAddrBytes)

	binary.BigEndian.PutUint16(buf[offset:offset+2], p.SourcePort)
	offset += 2

	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(destAddrBytes)))
	offset += 2
	copy(buf[offset:offset+len(destAddrBytes)], destAddrBytes)
	offset += len(destAddrBytes)

	binary.BigEndian.PutUint16(buf[offset:offset+2], p.DestPort)
	offset += 2

	copy(buf[offset:], p.Data)

	return buf
}

// DecodeUDPDataPayload decodes a UDP data payload
func DecodeUDPDataPayload(data []byte) (*UDPDataPayload, error) {
	if len(data) < 8 {
		return nil, ErrInvalidPayload
	}

	offset := 0

	srcAddrLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if offset+int(srcAddrLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	srcAddr := string(data[offset : offset+int(srcAddrLen)])
	offset += int(srcAddrLen)

	if offset+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	srcPort := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if offset+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	destAddrLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if offset+int(destAddrLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	destAddr := string(data[offset : offset+int(destAddrLen)])
	offset += int(destAddrLen)

	if offset+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	destPort := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	packetData := make([]byte, len(data)-offset)
	copy(packetData, data[offset:])

	return &UDPDataPayload{
		SourceAddr: srcAddr,
		SourcePort: srcPort,
		DestAddr:   destAddr,
		DestPort:   destPort,
		Data:       packetData,
	}, nil
}

// EncodeICMPDataPayload encodes an ICMP data payload
func EncodeICMPDataPayload(p *ICMPDataPayload) []byte {
	destAddrBytes := []byte(p.DestAddr)
	buf := make([]byte, 4+len(destAddrBytes)+len(p.Data))

	buf[0] = p.Type
	buf[1] = p.Code

	binary.BigEndian.PutUint16(buf[2:4], uint16(len(destAddrBytes)))
	copy(buf[4:4+len(destAddrBytes)], destAddrBytes)
	copy(buf[4+len(destAddrBytes):], p.Data)

	return buf
}

// DecodeICMPDataPayload decodes an ICMP data payload
func DecodeICMPDataPayload(data []byte) (*ICMPDataPayload, error) {
	if len(data) < 4 {
		return nil, ErrInvalidPayload
	}

	icmpType := data[0]
	code := data[1]

	addrLen := binary.BigEndian.Uint16(data[2:4])
	if 4+int(addrLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	destAddr := string(data[4 : 4+addrLen])

	packetData := make([]byte, len(data)-4-int(addrLen))
	copy(packetData, data[4+addrLen:])

	return &ICMPDataPayload{
		Type:     icmpType,
		Code:     code,
		DestAddr: destAddr,
		Data:     packetData,
	}, nil
}

// EncodeErrorPayload encodes an error payload
func EncodeErrorPayload(p *ErrorPayload) []byte {
	msgBytes := []byte(p.Message)
	buf := make([]byte, 4+len(msgBytes))

	binary.BigEndian.PutUint16(buf[0:2], p.Code)
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(msgBytes)))
	copy(buf[4:], msgBytes)

	return buf
}

// DecodeErrorPayload decodes an error payload
func DecodeErrorPayload(data []byte) (*ErrorPayload, error) {
	if len(data) < 4 {
		return nil, ErrInvalidPayload
	}

	code := binary.BigEndian.Uint16(data[0:2])
	msgLen := binary.BigEndian.Uint16(data[2:4])

	if 4+int(msgLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	msg := string(data[4 : 4+msgLen])

	return &ErrorPayload{
		Code:    code,
		Message: msg,
	}, nil
}

// EncodeLocalProxyStartPayload encodes a local proxy start payload
func EncodeLocalProxyStartPayload(p *LocalProxyStartPayload) []byte {
	ruleIDBytes := []byte(p.RuleID)
	protocolBytes := []byte(p.Protocol)
	targetAgentBytes := []byte(p.TargetAgentID)
	targetHostBytes := []byte(p.TargetHost)

	// 2 (ruleID len) + ruleID + 2 (protocol len) + protocol + 2 (listen port)
	// + 2 (target agent len) + target agent + 2 (target host len) + target host + 2 (target port)
	buf := make([]byte, 12+len(ruleIDBytes)+len(protocolBytes)+len(targetAgentBytes)+len(targetHostBytes))

	offset := 0
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(ruleIDBytes)))
	offset += 2
	copy(buf[offset:offset+len(ruleIDBytes)], ruleIDBytes)
	offset += len(ruleIDBytes)

	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(protocolBytes)))
	offset += 2
	copy(buf[offset:offset+len(protocolBytes)], protocolBytes)
	offset += len(protocolBytes)

	binary.BigEndian.PutUint16(buf[offset:offset+2], p.ListenPort)
	offset += 2

	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(targetAgentBytes)))
	offset += 2
	copy(buf[offset:offset+len(targetAgentBytes)], targetAgentBytes)
	offset += len(targetAgentBytes)

	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(targetHostBytes)))
	offset += 2
	copy(buf[offset:offset+len(targetHostBytes)], targetHostBytes)
	offset += len(targetHostBytes)

	binary.BigEndian.PutUint16(buf[offset:offset+2], p.TargetPort)

	return buf
}

// DecodeLocalProxyStartPayload decodes a local proxy start payload
func DecodeLocalProxyStartPayload(data []byte) (*LocalProxyStartPayload, error) {
	if len(data) < 12 {
		return nil, ErrInvalidPayload
	}

	offset := 0

	ruleIDLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if offset+int(ruleIDLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	ruleID := string(data[offset : offset+int(ruleIDLen)])
	offset += int(ruleIDLen)

	if offset+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	protocolLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if offset+int(protocolLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	protocol := string(data[offset : offset+int(protocolLen)])
	offset += int(protocolLen)

	if offset+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	listenPort := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if offset+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	targetAgentLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if offset+int(targetAgentLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	targetAgentID := string(data[offset : offset+int(targetAgentLen)])
	offset += int(targetAgentLen)

	if offset+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	targetHostLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if offset+int(targetHostLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	targetHost := string(data[offset : offset+int(targetHostLen)])
	offset += int(targetHostLen)

	if offset+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	targetPort := binary.BigEndian.Uint16(data[offset : offset+2])

	return &LocalProxyStartPayload{
		RuleID:        ruleID,
		Protocol:      protocol,
		ListenPort:    listenPort,
		TargetAgentID: targetAgentID,
		TargetHost:    targetHost,
		TargetPort:    targetPort,
	}, nil
}

// EncodeLocalProxyStopPayload encodes a local proxy stop payload
func EncodeLocalProxyStopPayload(p *LocalProxyStopPayload) []byte {
	ruleIDBytes := []byte(p.RuleID)
	buf := make([]byte, 2+len(ruleIDBytes))
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(ruleIDBytes)))
	copy(buf[2:], ruleIDBytes)
	return buf
}

// DecodeLocalProxyStopPayload decodes a local proxy stop payload
func DecodeLocalProxyStopPayload(data []byte) (*LocalProxyStopPayload, error) {
	if len(data) < 2 {
		return nil, ErrInvalidPayload
	}

	ruleIDLen := binary.BigEndian.Uint16(data[0:2])
	if 2+int(ruleIDLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	ruleID := string(data[2 : 2+ruleIDLen])

	return &LocalProxyStopPayload{
		RuleID: ruleID,
	}, nil
}

// EncodeP2PConnectPayload encodes a P2P connect payload
func EncodeP2PConnectPayload(p *P2PConnectPayload) []byte {
	srcAgentBytes := []byte(p.SourceAgentID)
	protocolBytes := []byte(p.Protocol)
	targetHostBytes := []byte(p.TargetHost)

	buf := make([]byte, 10+len(srcAgentBytes)+len(protocolBytes)+len(targetHostBytes))

	offset := 0
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(srcAgentBytes)))
	offset += 2
	copy(buf[offset:offset+len(srcAgentBytes)], srcAgentBytes)
	offset += len(srcAgentBytes)

	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(protocolBytes)))
	offset += 2
	copy(buf[offset:offset+len(protocolBytes)], protocolBytes)
	offset += len(protocolBytes)

	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(targetHostBytes)))
	offset += 2
	copy(buf[offset:offset+len(targetHostBytes)], targetHostBytes)
	offset += len(targetHostBytes)

	binary.BigEndian.PutUint16(buf[offset:offset+2], p.TargetPort)

	return buf
}

// DecodeP2PConnectPayload decodes a P2P connect payload
func DecodeP2PConnectPayload(data []byte) (*P2PConnectPayload, error) {
	if len(data) < 10 {
		return nil, ErrInvalidPayload
	}

	offset := 0

	srcAgentLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if offset+int(srcAgentLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	srcAgent := string(data[offset : offset+int(srcAgentLen)])
	offset += int(srcAgentLen)

	if offset+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	protocolLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if offset+int(protocolLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	protocol := string(data[offset : offset+int(protocolLen)])
	offset += int(protocolLen)

	if offset+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	targetHostLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if offset+int(targetHostLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	targetHost := string(data[offset : offset+int(targetHostLen)])
	offset += int(targetHostLen)

	if offset+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	targetPort := binary.BigEndian.Uint16(data[offset : offset+2])

	return &P2PConnectPayload{
		SourceAgentID: srcAgent,
		Protocol:      protocol,
		TargetHost:    targetHost,
		TargetPort:    targetPort,
	}, nil
}

// EncodeP2PDataPayload encodes a P2P data payload
func EncodeP2PDataPayload(p *P2PDataPayload) []byte {
	srcAgentBytes := []byte(p.SourceAgentID)
	buf := make([]byte, 2+len(srcAgentBytes)+len(p.Data))

	binary.BigEndian.PutUint16(buf[0:2], uint16(len(srcAgentBytes)))
	copy(buf[2:2+len(srcAgentBytes)], srcAgentBytes)
	copy(buf[2+len(srcAgentBytes):], p.Data)

	return buf
}

// DecodeP2PDataPayload decodes a P2P data payload
func DecodeP2PDataPayload(data []byte) (*P2PDataPayload, error) {
	if len(data) < 2 {
		return nil, ErrInvalidPayload
	}

	srcAgentLen := binary.BigEndian.Uint16(data[0:2])
	if 2+int(srcAgentLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	srcAgent := string(data[2 : 2+srcAgentLen])

	payloadData := make([]byte, len(data)-2-int(srcAgentLen))
	copy(payloadData, data[2+srcAgentLen:])

	return &P2PDataPayload{
		SourceAgentID: srcAgent,
		Data:          payloadData,
	}, nil
}

// EncodeAgentCloudProxyStartPayload encodes an agent-cloud proxy start payload
func EncodeAgentCloudProxyStartPayload(p *AgentCloudProxyStartPayload) []byte {
	ruleIDBytes := []byte(p.RuleID)
	protocolBytes := []byte(p.Protocol)
	targetHostBytes := []byte(p.TargetHost)

	// 2 (ruleID len) + ruleID + 2 (protocol len) + protocol + 2 (listen port)
	// + 2 (target host len) + target host + 2 (target port)
	buf := make([]byte, 10+len(ruleIDBytes)+len(protocolBytes)+len(targetHostBytes))

	offset := 0
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(ruleIDBytes)))
	offset += 2
	copy(buf[offset:offset+len(ruleIDBytes)], ruleIDBytes)
	offset += len(ruleIDBytes)

	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(protocolBytes)))
	offset += 2
	copy(buf[offset:offset+len(protocolBytes)], protocolBytes)
	offset += len(protocolBytes)

	binary.BigEndian.PutUint16(buf[offset:offset+2], p.ListenPort)
	offset += 2

	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(targetHostBytes)))
	offset += 2
	copy(buf[offset:offset+len(targetHostBytes)], targetHostBytes)
	offset += len(targetHostBytes)

	binary.BigEndian.PutUint16(buf[offset:offset+2], p.TargetPort)

	return buf
}

// DecodeAgentCloudProxyStartPayload decodes an agent-cloud proxy start payload
func DecodeAgentCloudProxyStartPayload(data []byte) (*AgentCloudProxyStartPayload, error) {
	if len(data) < 10 {
		return nil, ErrInvalidPayload
	}

	offset := 0

	ruleIDLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if offset+int(ruleIDLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	ruleID := string(data[offset : offset+int(ruleIDLen)])
	offset += int(ruleIDLen)

	if offset+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	protocolLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if offset+int(protocolLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	protocol := string(data[offset : offset+int(protocolLen)])
	offset += int(protocolLen)

	if offset+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	listenPort := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if offset+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	targetHostLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if offset+int(targetHostLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	targetHost := string(data[offset : offset+int(targetHostLen)])
	offset += int(targetHostLen)

	if offset+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	targetPort := binary.BigEndian.Uint16(data[offset : offset+2])

	return &AgentCloudProxyStartPayload{
		RuleID:     ruleID,
		Protocol:   protocol,
		ListenPort: listenPort,
		TargetHost: targetHost,
		TargetPort: targetPort,
	}, nil
}

// EncodeAgentCloudProxyStopPayload encodes an agent-cloud proxy stop payload
func EncodeAgentCloudProxyStopPayload(p *AgentCloudProxyStopPayload) []byte {
	ruleIDBytes := []byte(p.RuleID)
	buf := make([]byte, 2+len(ruleIDBytes))
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(ruleIDBytes)))
	copy(buf[2:], ruleIDBytes)
	return buf
}

// DecodeAgentCloudProxyStopPayload decodes an agent-cloud proxy stop payload
func DecodeAgentCloudProxyStopPayload(data []byte) (*AgentCloudProxyStopPayload, error) {
	if len(data) < 2 {
		return nil, ErrInvalidPayload
	}

	ruleIDLen := binary.BigEndian.Uint16(data[0:2])
	if 2+int(ruleIDLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	ruleID := string(data[2 : 2+ruleIDLen])

	return &AgentCloudProxyStopPayload{
		RuleID: ruleID,
	}, nil
}

// EncodeAgentCloudConnectPayload encodes an agent-cloud connect payload
func EncodeAgentCloudConnectPayload(p *AgentCloudConnectPayload) []byte {
	protocolBytes := []byte(p.Protocol)
	targetHostBytes := []byte(p.TargetHost)

	buf := make([]byte, 6+len(protocolBytes)+len(targetHostBytes))

	offset := 0
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(protocolBytes)))
	offset += 2
	copy(buf[offset:offset+len(protocolBytes)], protocolBytes)
	offset += len(protocolBytes)

	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(targetHostBytes)))
	offset += 2
	copy(buf[offset:offset+len(targetHostBytes)], targetHostBytes)
	offset += len(targetHostBytes)

	binary.BigEndian.PutUint16(buf[offset:offset+2], p.TargetPort)

	return buf
}

// DecodeAgentCloudConnectPayload decodes an agent-cloud connect payload
func DecodeAgentCloudConnectPayload(data []byte) (*AgentCloudConnectPayload, error) {
	if len(data) < 6 {
		return nil, ErrInvalidPayload
	}

	offset := 0

	protocolLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if offset+int(protocolLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	protocol := string(data[offset : offset+int(protocolLen)])
	offset += int(protocolLen)

	if offset+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	targetHostLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if offset+int(targetHostLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	targetHost := string(data[offset : offset+int(targetHostLen)])
	offset += int(targetHostLen)

	if offset+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	targetPort := binary.BigEndian.Uint16(data[offset : offset+2])

	return &AgentCloudConnectPayload{
		Protocol:   protocol,
		TargetHost: targetHost,
		TargetPort: targetPort,
	}, nil
}

// EncodeRuleAuthPayload encodes a rule auth payload
func EncodeRuleAuthPayload(p *RuleAuthPayload) []byte {
	tokenBytes := []byte(p.Token)
	agentIDBytes := []byte(p.AgentID)
	ruleIDBytes := []byte(p.RuleID)

	buf := make([]byte, 6+len(tokenBytes)+len(agentIDBytes)+len(ruleIDBytes))

	offset := 0
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(tokenBytes)))
	offset += 2
	copy(buf[offset:offset+len(tokenBytes)], tokenBytes)
	offset += len(tokenBytes)

	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(agentIDBytes)))
	offset += 2
	copy(buf[offset:offset+len(agentIDBytes)], agentIDBytes)
	offset += len(agentIDBytes)

	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(ruleIDBytes)))
	offset += 2
	copy(buf[offset:], ruleIDBytes)

	return buf
}

// DecodeRuleAuthPayload decodes a rule auth payload
func DecodeRuleAuthPayload(data []byte) (*RuleAuthPayload, error) {
	if len(data) < 6 {
		return nil, ErrInvalidPayload
	}

	offset := 0

	tokenLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if offset+int(tokenLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	token := string(data[offset : offset+int(tokenLen)])
	offset += int(tokenLen)

	if offset+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	agentIDLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if offset+int(agentIDLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	agentID := string(data[offset : offset+int(agentIDLen)])
	offset += int(agentIDLen)

	if offset+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	ruleIDLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if offset+int(ruleIDLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	ruleID := string(data[offset : offset+int(ruleIDLen)])

	return &RuleAuthPayload{
		Token:   token,
		AgentID: agentID,
		RuleID:  ruleID,
	}, nil
}

// EncodeRuleAuthResponsePayload encodes a rule auth response payload
func EncodeRuleAuthResponsePayload(p *RuleAuthResponsePayload) []byte {
	ruleIDBytes := []byte(p.RuleID)
	errBytes := []byte(p.Error)

	buf := make([]byte, 5+len(ruleIDBytes)+len(errBytes))

	if p.Success {
		buf[0] = 1
	} else {
		buf[0] = 0
	}

	binary.BigEndian.PutUint16(buf[1:3], uint16(len(ruleIDBytes)))
	copy(buf[3:3+len(ruleIDBytes)], ruleIDBytes)

	offset := 3 + len(ruleIDBytes)
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(errBytes)))
	copy(buf[offset+2:], errBytes)

	return buf
}

// DecodeRuleAuthResponsePayload decodes a rule auth response payload
func DecodeRuleAuthResponsePayload(data []byte) (*RuleAuthResponsePayload, error) {
	if len(data) < 5 {
		return nil, ErrInvalidPayload
	}

	success := data[0] == 1

	ruleIDLen := binary.BigEndian.Uint16(data[1:3])
	if 3+int(ruleIDLen)+2 > len(data) {
		return nil, ErrInvalidPayload
	}
	ruleID := string(data[3 : 3+ruleIDLen])

	offset := 3 + int(ruleIDLen)
	errLen := binary.BigEndian.Uint16(data[offset : offset+2])
	if offset+2+int(errLen) > len(data) {
		return nil, ErrInvalidPayload
	}
	errMsg := string(data[offset+2 : offset+2+int(errLen)])

	return &RuleAuthResponsePayload{
		Success: success,
		RuleID:  ruleID,
		Error:   errMsg,
	}, nil
}

