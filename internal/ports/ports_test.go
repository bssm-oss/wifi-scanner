package ports

import (
	"reflect"
	"testing"
)

func TestParseTCPDefault(t *testing.T) {
	got, err := ParseTCP("", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("expected default ports")
	}
	if got[0] <= 0 {
		t.Fatalf("invalid first port: %d", got[0])
	}
}

func TestParseTCPDeepUsesFullRange(t *testing.T) {
	got, err := ParseTCP("", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 65535 || got[0] != 1 || got[len(got)-1] != 65535 {
		t.Fatalf("unexpected deep range: len=%d first=%d last=%d", len(got), got[0], got[len(got)-1])
	}
}

func TestParsePortListAndRange(t *testing.T) {
	got, err := ParseTCP("80,22,8000-8002,22", false)
	if err != nil {
		t.Fatal(err)
	}
	want := []int{22, 80, 8000, 8001, 8002}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParseInvalidPort(t *testing.T) {
	if _, err := ParseTCP("0", false); err == nil {
		t.Fatal("expected invalid port error")
	}
	if _, err := ParseTCP("90-80", false); err == nil {
		t.Fatal("expected descending range error")
	}
}
