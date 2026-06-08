package target

import (
	"reflect"
	"testing"
)

func TestExpandCIDRExcludesNetworkAndBroadcast(t *testing.T) {
	got, err := Expand("192.168.1.0/30", Options{MaxHosts: 10})
	if err != nil {
		t.Fatal(err)
	}
	var ips []string
	for _, ip := range got {
		ips = append(ips, ip.String())
	}
	want := []string{"192.168.1.1", "192.168.1.2"}
	if !reflect.DeepEqual(ips, want) {
		t.Fatalf("got %v want %v", ips, want)
	}
}

func TestExpandShortRange(t *testing.T) {
	got, err := Expand("10.0.0.10-12", Options{MaxHosts: 10})
	if err != nil {
		t.Fatal(err)
	}
	var ips []string
	for _, ip := range got {
		ips = append(ips, ip.String())
	}
	want := []string{"10.0.0.10", "10.0.0.11", "10.0.0.12"}
	if !reflect.DeepEqual(ips, want) {
		t.Fatalf("got %v want %v", ips, want)
	}
}

func TestExpandRejectsPublicByDefault(t *testing.T) {
	if _, err := Expand("8.8.8.8", Options{MaxHosts: 1}); err == nil {
		t.Fatal("expected public target rejection")
	}
	if _, err := Expand("8.8.8.8", Options{AllowPublic: true, MaxHosts: 1}); err != nil {
		t.Fatalf("allow public should pass: %v", err)
	}
}

func TestExpandMaxHosts(t *testing.T) {
	if _, err := Expand("192.168.1.0/24", Options{MaxHosts: 10}); err == nil {
		t.Fatal("expected max hosts error")
	}
}
