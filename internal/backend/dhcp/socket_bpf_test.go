package dhcp

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestSplitBPF(t *testing.T) {
	data := make([]byte, 64)
	binary.LittleEndian.PutUint32(data[16:], 5)
	binary.LittleEndian.PutUint16(data[24:], 26)
	copy(data[26:], "hello")
	binary.LittleEndian.PutUint32(data[32+16:], 2)
	binary.LittleEndian.PutUint16(data[32+24:], 26)
	frame, rest := splitBPF(data[:60])
	if !bytes.Equal(frame, []byte("hello")) || len(rest) != 28 {
		t.Fatalf("frame %q, rest %d", frame, len(rest))
	}
	frame, rest = splitBPF(rest)
	if len(frame) != 2 || rest != nil {
		t.Fatalf("frame %q, rest %d", frame, len(rest))
	}
}
