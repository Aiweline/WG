package codec

import (
	"encoding/binary"
	"fmt"
	"math"
	"sort"
)

const TLVHeaderSize = 3

type TLVType uint8

const (
	TLVEgressPolicyVersion TLVType = 0x0C
	TLVDNSParameters       TLVType = 0x0D
	TLVVersion             TLVType = 0x81
	TLVDeploymentID        TLVType = 0x82
	TLVClientCID           TLVType = 0x83
	TLVServerCID           TLVType = 0x84
	TLVCapabilities        TLVType = 0x85
	TLVAddressFamilies     TLVType = 0x86
	TLVMaxDatagramSize     TLVType = 0x87
	TLVIPv4Lease           TLVType = 0x88
	TLVIPv6Lease           TLVType = 0x89
	TLVTunnelMTU           TLVType = 0x8A
	TLVLeaseSeconds        TLVType = 0x8B
	TLVClientStaticKey     TLVType = 0x8C
	TLVEnrollmentTokenID   TLVType = 0x8D
	TLVEnrollmentProof     TLVType = 0x8E
)

// TLVContext applies the occurrence rules from the INITIAL or HANDSHAKE table.
type TLVContext uint8

const (
	TLVContextAny TLVContext = iota
	TLVContextInitial
	TLVContextHandshake
)

// TLV is a detached field. Value length is encoded as uint16.
type TLV struct {
	Type  TLVType
	Value []byte
}

// Critical reports whether the high bit is set.
func (field TLV) Critical() bool { return uint8(field.Type)&0x80 != 0 }

// ParseTLVs parses a canonical stream. Unknown non-critical fields are retained
// for canonical round trips; unknown critical fields are rejected.
func ParseTLVs(data []byte) ([]TLV, error) {
	if len(data) > math.MaxUint16 {
		return nil, decodeError(ErrLimit, 0, "tlv.stream", "exceeds uint16")
	}
	fields := make([]TLV, 0, 8)
	offset := 0
	var previous TLVType
	havePrevious := false
	for offset < len(data) {
		if len(data)-offset < TLVHeaderSize {
			return nil, decodeError(ErrTruncated, offset, "tlv.header", "need 3 bytes")
		}
		fieldType := TLVType(data[offset])
		length := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
		if havePrevious && fieldType <= previous {
			if fieldType == previous {
				return nil, decodeError(ErrDuplicateTLV, offset, "tlv.type", fmt.Sprintf("0x%02x", uint8(fieldType)))
			}
			return nil, decodeError(ErrTLVOrder, offset, "tlv.type", "types must be strictly increasing")
		}
		valueOffset := offset + TLVHeaderSize
		if length > len(data)-valueOffset {
			return nil, decodeError(ErrTruncated, valueOffset, "tlv.value", fmt.Sprintf("type 0x%02x declares %d bytes", uint8(fieldType), length))
		}
		field := TLV{Type: fieldType, Value: append([]byte(nil), data[valueOffset:valueOffset+length]...)}
		if err := validateTLVField(field, offset); err != nil {
			return nil, err
		}
		fields = append(fields, field)
		previous = fieldType
		havePrevious = true
		offset = valueOffset + length
	}
	return fields, nil
}

// ParseTLVsFor additionally validates placement, required fields, and paired
// enrollment fields for one handshake message.
func ParseTLVsFor(data []byte, context TLVContext) ([]TLV, error) {
	fields, err := ParseTLVs(data)
	if err != nil {
		return nil, err
	}
	if err := ValidateTLVs(fields, context); err != nil {
		return nil, err
	}
	return fields, nil
}

// MarshalTLVs sorts fields by type and emits the unique canonical stream.
func MarshalTLVs(fields []TLV) ([]byte, error) {
	canonical := cloneTLVs(fields)
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].Type < canonical[j].Type })

	total := 0
	for index, field := range canonical {
		if index > 0 && field.Type == canonical[index-1].Type {
			return nil, decodeError(ErrDuplicateTLV, -1, "tlv.type", fmt.Sprintf("0x%02x", uint8(field.Type)))
		}
		if err := validateTLVField(field, -1); err != nil {
			return nil, err
		}
		if len(field.Value) > math.MaxUint16 {
			return nil, decodeError(ErrTLVLength, -1, "tlv.value", "does not fit uint16")
		}
		if total > math.MaxUint16-TLVHeaderSize-len(field.Value) {
			return nil, decodeError(ErrLength, -1, "tlv.stream", "does not fit uint16")
		}
		total += TLVHeaderSize + len(field.Value)
	}

	data := make([]byte, total)
	offset := 0
	for _, field := range canonical {
		data[offset] = byte(field.Type)
		binary.BigEndian.PutUint16(data[offset+1:offset+3], uint16(len(field.Value)))
		copy(data[offset+3:], field.Value)
		offset += TLVHeaderSize + len(field.Value)
	}
	return data, nil
}

// MarshalTLVsFor validates context before canonical serialization.
func MarshalTLVsFor(fields []TLV, context TLVContext) ([]byte, error) {
	if err := ValidateTLVs(fields, context); err != nil {
		return nil, err
	}
	return MarshalTLVs(fields)
}

// ValidateTLVs validates a detached slice regardless of its current ordering.
func ValidateTLVs(fields []TLV, context TLVContext) error {
	if context != TLVContextAny && context != TLVContextInitial && context != TLVContextHandshake {
		return decodeError(ErrTLVContext, -1, "tlv.context", "unknown context")
	}
	seen := make(map[TLVType]TLV, len(fields))
	for _, field := range fields {
		if _, exists := seen[field.Type]; exists {
			return decodeError(ErrDuplicateTLV, -1, "tlv.type", fmt.Sprintf("0x%02x", uint8(field.Type)))
		}
		if err := validateTLVField(field, -1); err != nil {
			return err
		}
		if context != TLVContextAny && knownTLV(field.Type) && !allowedInContext(field.Type, context) {
			return decodeError(ErrTLVContext, -1, "tlv.type", fmt.Sprintf("0x%02x is not allowed", uint8(field.Type)))
		}
		seen[field.Type] = field
	}

	_, tokenPresent := seen[TLVEnrollmentTokenID]
	_, proofPresent := seen[TLVEnrollmentProof]
	if tokenPresent != proofPresent {
		return decodeError(ErrTLVContext, -1, "enrollment", "token id and proof must appear together")
	}

	if lease, ok := seen[TLVIPv4Lease]; ok && lease.Value[4] > 32 {
		return decodeError(ErrTLVLength, -1, "ipv4_lease.prefix", "prefix exceeds 32")
	}
	if lease, ok := seen[TLVIPv6Lease]; ok && lease.Value[16] > 128 {
		return decodeError(ErrTLVLength, -1, "ipv6_lease.prefix", "prefix exceeds 128")
	}

	var required []TLVType
	switch context {
	case TLVContextInitial:
		required = []TLVType{
			TLVVersion, TLVDeploymentID, TLVClientCID, TLVCapabilities,
			TLVAddressFamilies, TLVMaxDatagramSize, TLVClientStaticKey,
		}
	case TLVContextHandshake:
		required = []TLVType{
			TLVVersion, TLVDeploymentID, TLVClientCID, TLVServerCID,
			TLVCapabilities, TLVAddressFamilies, TLVMaxDatagramSize,
			TLVTunnelMTU, TLVLeaseSeconds,
		}
	}
	for _, fieldType := range required {
		if _, ok := seen[fieldType]; !ok {
			return decodeError(ErrMissingTLV, -1, "tlv", fmt.Sprintf("missing 0x%02x", uint8(fieldType)))
		}
	}
	if context == TLVContextHandshake {
		_, hasIPv4 := seen[TLVIPv4Lease]
		_, hasIPv6 := seen[TLVIPv6Lease]
		if !hasIPv4 && !hasIPv6 {
			return decodeError(ErrMissingTLV, -1, "tlv", "HANDSHAKE requires an IPv4 or IPv6 lease")
		}
	}
	return nil
}

// FindTLV returns a detached field value.
func FindTLV(fields []TLV, fieldType TLVType) ([]byte, bool) {
	for _, field := range fields {
		if field.Type == fieldType {
			return append([]byte(nil), field.Value...), true
		}
	}
	return nil, false
}

func validateTLVField(field TLV, offset int) error {
	if field.Critical() && !knownTLV(field.Type) {
		return decodeError(ErrUnknownCriticalTLV, offset, "tlv.type", fmt.Sprintf("0x%02x", uint8(field.Type)))
	}
	if length, fixed := fixedTLVLength(field.Type); fixed && len(field.Value) != length {
		return decodeError(ErrTLVLength, offset, "tlv.value", fmt.Sprintf("type 0x%02x requires %d bytes", uint8(field.Type), length))
	}
	return nil
}

func knownTLV(fieldType TLVType) bool {
	return fieldType == TLVEgressPolicyVersion || fieldType == TLVDNSParameters ||
		(fieldType >= TLVVersion && fieldType <= TLVEnrollmentProof)
}

func fixedTLVLength(fieldType TLVType) (int, bool) {
	switch fieldType {
	case TLVEgressPolicyVersion, TLVClientCID, TLVServerCID, TLVCapabilities:
		return 8, true
	case TLVVersion, TLVAddressFamilies:
		return 1, true
	case TLVDeploymentID, TLVEnrollmentTokenID:
		return 16, true
	case TLVMaxDatagramSize, TLVTunnelMTU:
		return 2, true
	case TLVIPv4Lease:
		return 5, true
	case TLVIPv6Lease:
		return 17, true
	case TLVLeaseSeconds:
		return 4, true
	case TLVClientStaticKey, TLVEnrollmentProof:
		return 32, true
	default:
		return 0, false
	}
}

func allowedInContext(fieldType TLVType, context TLVContext) bool {
	switch context {
	case TLVContextInitial:
		switch fieldType {
		case TLVVersion, TLVDeploymentID, TLVClientCID, TLVCapabilities,
			TLVAddressFamilies, TLVMaxDatagramSize, TLVClientStaticKey,
			TLVEnrollmentTokenID, TLVEnrollmentProof:
			return true
		}
	case TLVContextHandshake:
		switch fieldType {
		case TLVEgressPolicyVersion, TLVDNSParameters, TLVVersion,
			TLVDeploymentID, TLVClientCID, TLVServerCID, TLVCapabilities,
			TLVAddressFamilies, TLVMaxDatagramSize, TLVIPv4Lease,
			TLVIPv6Lease, TLVTunnelMTU, TLVLeaseSeconds:
			return true
		}
	}
	return false
}

func cloneTLVs(fields []TLV) []TLV {
	result := make([]TLV, len(fields))
	for index, field := range fields {
		result[index] = TLV{Type: field.Type, Value: append([]byte(nil), field.Value...)}
	}
	return result
}
