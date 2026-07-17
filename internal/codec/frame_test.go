package codec

import (
	"bytes"
	"errors"
	"testing"
)

func TestIPPacketFramesRoundTrip(t *testing.T) {
	t.Parallel()

	for _, packet := range [][]byte{validIPv4Packet(), validIPv6Packet()} {
		encoded, err := MarshalFrames([]Frame{{Type: FrameIPPacket, Body: packet}}, 0)
		if err != nil {
			t.Fatalf("MarshalFrames: %v", err)
		}
		frames, err := ParseFrames(encoded, 0)
		if err != nil {
			t.Fatalf("ParseFrames: %v", err)
		}
		if len(frames) != 1 || !bytes.Equal(frames[0].Body, packet) {
			t.Fatalf("frames = %+v", frames)
		}
		frames[0].Body[0] = 0
		if packet[0] == 0 {
			t.Fatal("test packet unexpectedly mutable")
		}
	}
}

func TestControlFramesAndCloseRoundTrip(t *testing.T) {
	t.Parallel()

	closeBody, err := EncodeClose(7, "peer requested shutdown")
	if err != nil {
		t.Fatal(err)
	}
	controls := []Frame{
		{Type: FramePing, Body: bytes.Repeat([]byte{1}, ChallengeBodySize)},
		{Type: FramePong, Body: bytes.Repeat([]byte{2}, ChallengeBodySize)},
		{Type: FramePathChallenge, Body: []byte{3, 4}},
		{Type: FramePathResponse, Body: []byte{3, 4}},
		{Type: FrameLeaseUpdate, Body: []byte{5}},
		{Type: FrameClose, Body: closeBody},
	}
	encoded, err := MarshalFrames(controls, 0)
	if err != nil {
		t.Fatalf("MarshalFrames: %v", err)
	}
	parsed, err := ParseFrames(encoded, 0)
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	if len(parsed) != len(controls) {
		t.Fatalf("got %d frames, want %d", len(parsed), len(controls))
	}
	reason, diagnostic, err := DecodeClose(parsed[len(parsed)-1].Body)
	if err != nil || reason != 7 || diagnostic != "peer requested shutdown" {
		t.Fatalf("DecodeClose = %d, %q, %v", reason, diagnostic, err)
	}
}

func TestConfirmMustBeFollowedByPing(t *testing.T) {
	t.Parallel()

	confirm := Frame{Type: FrameConfirm, Body: make([]byte, ConfirmBodySize)}
	ping := Frame{Type: FramePing, Body: make([]byte, ChallengeBodySize)}
	if _, err := MarshalFrames([]Frame{confirm, ping}, 0); err != nil {
		t.Fatalf("valid confirmation flight: %v", err)
	}
	for _, frames := range [][]Frame{{confirm}, {ping, confirm}, {confirm, ping, ping}, {confirm, confirm}} {
		if _, err := MarshalFrames(frames, 0); !errors.Is(err, ErrFrameConstraint) {
			t.Fatalf("frames %+v error = %v, want ErrFrameConstraint", frames, err)
		}
	}
}

func TestFrameRejectMatrix(t *testing.T) {
	t.Parallel()

	validPing, err := MarshalFrames([]Frame{{Type: FramePing, Body: make([]byte, ChallengeBodySize)}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"empty", nil, ErrLength},
		{"partial header", []byte{byte(FramePing), 0, 0}, ErrTruncated},
		{"unknown type", []byte{0xFF, 0, 0, 0}, ErrUnknownFrameType},
		{"flags", []byte{byte(FramePing), 1, 0, ChallengeBodySize}, ErrFrameFlags},
		{"truncated body", []byte{byte(FramePing), 0, 0, ChallengeBodySize, 1}, ErrTruncated},
		{"trailing partial", append(append([]byte(nil), validPing...), 0), ErrTruncated},
		{"ping length", []byte{byte(FramePing), 0, 0, 7, 1, 2, 3, 4, 5, 6, 7}, ErrLength},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseFrames(test.data, 0)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestFrameCombinationAndIPValidation(t *testing.T) {
	t.Parallel()

	ip := Frame{Type: FrameIPPacket, Body: validIPv4Packet()}
	ping := Frame{Type: FramePing, Body: make([]byte, ChallengeBodySize)}
	if _, err := MarshalFrames([]Frame{ip, ping}, 0); !errors.Is(err, ErrFrameConstraint) {
		t.Fatalf("IP plus control error = %v", err)
	}
	if _, err := MarshalFrames([]Frame{ip, ip}, 0); !errors.Is(err, ErrFrameConstraint) {
		t.Fatalf("two IP error = %v", err)
	}

	badVersion := validIPv4Packet()
	badVersion[0] = 0x75
	if _, err := MarshalFrames([]Frame{{Type: FrameIPPacket, Body: badVersion}}, 0); !errors.Is(err, ErrIPPacket) {
		t.Fatalf("bad version error = %v", err)
	}
	badLength := validIPv6Packet()
	badLength[5] = 1
	if _, err := MarshalFrames([]Frame{{Type: FrameIPPacket, Body: badLength}}, 0); !errors.Is(err, ErrIPPacket) {
		t.Fatalf("bad IPv6 length error = %v", err)
	}
}

func TestCloseValidation(t *testing.T) {
	t.Parallel()

	if _, err := EncodeClose(1, string([]byte{0xFF})); !errors.Is(err, ErrUTF8) {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
	if _, err := EncodeClose(1, string(bytes.Repeat([]byte{'x'}, DefaultMaxCloseTextLength+1))); !errors.Is(err, ErrLimit) {
		t.Fatalf("long diagnostic error = %v", err)
	}
	if _, _, err := DecodeClose([]byte{0}); !errors.Is(err, ErrTruncated) {
		t.Fatalf("short close error = %v", err)
	}
	if _, _, err := DecodeClose([]byte{0, 1, 0xFF}); !errors.Is(err, ErrUTF8) {
		t.Fatalf("bad close UTF-8 error = %v", err)
	}
}

func validIPv4Packet() []byte {
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[2] = 0
	packet[3] = byte(len(packet))
	return packet
}

func validIPv6Packet() []byte {
	packet := make([]byte, 40)
	packet[0] = 0x60
	return packet
}
