package codec

import (
	"bytes"
	"errors"
	"testing"
)

func TestInitialTLVCanonicalRoundTrip(t *testing.T) {
	t.Parallel()

	fields := initialTLVs()
	fields = append(fields, TLV{Type: 0x01, Value: []byte("optional")})
	encoded, err := MarshalTLVsFor(fields, TLVContextInitial)
	if err != nil {
		t.Fatalf("MarshalTLVsFor: %v", err)
	}
	if encoded[0] != 0x01 {
		t.Fatalf("serializer did not sort fields: %x", encoded)
	}
	parsed, err := ParseTLVsFor(encoded, TLVContextInitial)
	if err != nil {
		t.Fatalf("ParseTLVsFor: %v", err)
	}
	reencoded, err := MarshalTLVsFor(parsed, TLVContextInitial)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatalf("non-canonical round trip:\n%x\n%x", encoded, reencoded)
	}
	value, ok := FindTLV(parsed, 0x01)
	if !ok || string(value) != "optional" {
		t.Fatalf("unknown non-critical TLV was not retained: %q, %v", value, ok)
	}
	value[0] = 'X'
	valueAgain, _ := FindTLV(parsed, 0x01)
	if string(valueAgain) != "optional" {
		t.Fatal("FindTLV exposed mutable storage")
	}
}

func TestHandshakeTLVValidation(t *testing.T) {
	t.Parallel()

	fields := handshakeTLVs()
	encoded, err := MarshalTLVsFor(fields, TLVContextHandshake)
	if err != nil {
		t.Fatalf("MarshalTLVsFor: %v", err)
	}
	if _, err := ParseTLVsFor(encoded, TLVContextHandshake); err != nil {
		t.Fatalf("ParseTLVsFor: %v", err)
	}

	withoutLease := removeTLV(fields, TLVIPv4Lease)
	if _, err := MarshalTLVsFor(withoutLease, TLVContextHandshake); !errors.Is(err, ErrMissingTLV) {
		t.Fatalf("missing lease error = %v", err)
	}
	badPrefix := cloneTLVs(fields)
	for index := range badPrefix {
		if badPrefix[index].Type == TLVIPv4Lease {
			badPrefix[index].Value[4] = 33
		}
	}
	if _, err := MarshalTLVsFor(badPrefix, TLVContextHandshake); !errors.Is(err, ErrTLVLength) {
		t.Fatalf("bad prefix error = %v", err)
	}
}

func TestTLVRejectMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"unknown critical", []byte{0x90, 0, 0}, ErrUnknownCriticalTLV},
		{"duplicate", []byte{0x01, 0, 0, 0x01, 0, 0}, ErrDuplicateTLV},
		{"out of order", []byte{0x02, 0, 0, 0x01, 0, 0}, ErrTLVOrder},
		{"fixed length", []byte{byte(TLVVersion), 0, 2, 1, 2}, ErrTLVLength},
		{"truncated value", []byte{0x01, 0, 2, 1}, ErrTruncated},
		{"trailing partial header", []byte{0x01, 0, 0, 0x02}, ErrTruncated},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseTLVs(test.data)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestTLVContextAndEnrollmentPair(t *testing.T) {
	t.Parallel()

	missing := removeTLV(initialTLVs(), TLVVersion)
	if err := ValidateTLVs(missing, TLVContextInitial); !errors.Is(err, ErrMissingTLV) {
		t.Fatalf("missing error = %v", err)
	}
	wrongContext := append(initialTLVs(), fixedTLV(TLVServerCID, 8))
	if err := ValidateTLVs(wrongContext, TLVContextInitial); !errors.Is(err, ErrTLVContext) {
		t.Fatalf("context error = %v", err)
	}
	onlyToken := append(initialTLVs(), fixedTLV(TLVEnrollmentTokenID, 16))
	if err := ValidateTLVs(onlyToken, TLVContextInitial); !errors.Is(err, ErrTLVContext) {
		t.Fatalf("enrollment pair error = %v", err)
	}
	pair := append(initialTLVs(), fixedTLV(TLVEnrollmentTokenID, 16), fixedTLV(TLVEnrollmentProof, 32))
	if err := ValidateTLVs(pair, TLVContextInitial); err != nil {
		t.Fatalf("valid enrollment pair: %v", err)
	}
}

func initialTLVs() []TLV {
	return []TLV{
		fixedTLV(TLVClientStaticKey, 32),
		fixedTLV(TLVMaxDatagramSize, 2),
		fixedTLV(TLVAddressFamilies, 1),
		fixedTLV(TLVCapabilities, 8),
		fixedTLV(TLVClientCID, 8),
		fixedTLV(TLVDeploymentID, 16),
		{Type: TLVVersion, Value: []byte{Version1}},
	}
}

func handshakeTLVs() []TLV {
	lease := fixedTLV(TLVIPv4Lease, 5)
	lease.Value[4] = 24
	return []TLV{
		fixedTLV(TLVLeaseSeconds, 4),
		fixedTLV(TLVTunnelMTU, 2),
		lease,
		fixedTLV(TLVMaxDatagramSize, 2),
		fixedTLV(TLVAddressFamilies, 1),
		fixedTLV(TLVCapabilities, 8),
		fixedTLV(TLVServerCID, 8),
		fixedTLV(TLVClientCID, 8),
		fixedTLV(TLVDeploymentID, 16),
		{Type: TLVVersion, Value: []byte{Version1}},
	}
}

func fixedTLV(fieldType TLVType, length int) TLV {
	return TLV{Type: fieldType, Value: bytes.Repeat([]byte{byte(fieldType)}, length)}
}

func removeTLV(fields []TLV, fieldType TLVType) []TLV {
	result := make([]TLV, 0, len(fields))
	for _, field := range fields {
		if field.Type != fieldType {
			result = append(result, field)
		}
	}
	return result
}
