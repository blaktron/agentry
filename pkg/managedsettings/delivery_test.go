package managedsettings

import (
	"bytes"
	"strings"
	"testing"
)

func testDelivery() Delivery {
	return Delivery{Registry: "https://registry.example", Org: "acme", Account: "6f1c9a52-6c2e-4d7e-9a43-2b0f6c1d8e11",
		Key: "00000000-0000-4000-8000-000000000001", Rev: 3}
}

func TestADeliveredKeyOpensOnlyForItsRequest(t *testing.T) {
	k, err := NewDeliveryKey()
	if err != nil {
		t.Fatal(err)
	}
	d := testDelivery()
	value := []byte("sk-search-value")
	sealed, err := SealDelivery(k.PublicKey(), d, value)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, value) {
		t.Fatal("the sealed key carries the value in the clear")
	}
	got, err := k.Open(d, sealed)
	if err != nil || string(got) != string(value) {
		t.Fatalf("open: %q %v", got, err)
	}

	// Any other bound field, any other key pair, any changed byte: it does
	// not open.
	changed := map[string]Delivery{}
	for name, f := range map[string]func(*Delivery){
		"registry": func(x *Delivery) { x.Registry = "https://other.example" },
		"org":      func(x *Delivery) { x.Org = "globex" },
		"account":  func(x *Delivery) { x.Account = "7a1c9a52-6c2e-4d7e-9a43-2b0f6c1d8e11" },
		"key":      func(x *Delivery) { x.Key = "00000000-0000-4000-8000-000000000002" },
		"rev":      func(x *Delivery) { x.Rev = 4 },
	} {
		x := d
		f(&x)
		changed[name] = x
	}
	for name, x := range changed {
		if _, err := k.Open(x, sealed); err == nil {
			t.Errorf("a seal opened with another %s", name)
		}
	}
	other, _ := NewDeliveryKey()
	if _, err := other.Open(d, sealed); err == nil {
		t.Error("a seal opened with another key pair")
	}
	for _, i := range []int{0, len(sealed) / 2, len(sealed) - 1} {
		bad := bytes.Clone(sealed)
		bad[i] ^= 1
		if _, err := k.Open(d, bad); err == nil {
			t.Errorf("a seal changed at byte %d opened", i)
		}
	}
}

func TestADeliveryRefusesABadPublicKeyOrRequest(t *testing.T) {
	k, _ := NewDeliveryKey()
	d := testDelivery()
	pub := k.PublicKey()
	for name, p := range map[string][]byte{
		"empty":     nil,
		"short":     pub[:len(pub)-1],
		"long":      append(bytes.Clone(pub), 0),
		"x25519":    bytes.Repeat([]byte{9}, 32),
		"arbitrary": []byte(strings.Repeat("k", 64)),
	} {
		if _, err := SealDelivery(p, d, []byte("v")); err == nil || !strings.Contains(err.Error(), DeliverySuite) {
			t.Errorf("%s public key: %v", name, err)
		}
	}
	for name, x := range map[string]Delivery{
		"no registry": {Org: d.Org, Account: d.Account, Key: d.Key, Rev: d.Rev},
		"no org":      {Registry: d.Registry, Account: d.Account, Key: d.Key, Rev: d.Rev},
		"no account":  {Registry: d.Registry, Org: d.Org, Key: d.Key, Rev: d.Rev},
		"bad key":     {Registry: d.Registry, Org: d.Org, Account: d.Account, Key: "../x", Rev: d.Rev},
		"no rev":      {Registry: d.Registry, Org: d.Org, Account: d.Account, Key: d.Key},
	} {
		if _, err := SealDelivery(pub, x, []byte("v")); err == nil {
			t.Errorf("%s: sealed", name)
		}
	}
	if _, err := SealDelivery(pub, d, nil); err == nil {
		t.Error("an empty key was sealed")
	}
	if _, err := SealDelivery(pub, d, make([]byte, MaxDeliveredKey+1)); err == nil {
		t.Error("an over-long key was sealed")
	}
}
