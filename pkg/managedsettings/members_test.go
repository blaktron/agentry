package managedsettings

import (
	"errors"
	"strings"
	"testing"
)

const (
	alice = "7a0b3c1e-0000-4000-8000-000000000001"
	bob   = "7a0b3c1e-0000-4000-8000-000000000002"
	carol = "7a0b3c1e-0000-4000-8000-000000000003"
)

// boundDoc is a document bound to accounts.
func boundDoc(t *testing.T, accounts ...string) Document {
	t.Helper()
	m, err := BindMembers(accounts)
	if err != nil {
		t.Fatal(err)
	}
	d := validDoc()
	d.Schema, d.Members = SchemaMembers, m
	return d
}

// A document signed for one combination of teams, put in place of another
// member's at the same version, opens with the registry's key and is
// refused for that member's account; it applies to the accounts it names.
func TestABoundDocumentIsRefusedForAnotherMember(t *testing.T) {
	k := newKey(t)
	payload, err := Seal(boundDoc(t, alice, bob))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Open(Wrap(payload, k.sign(t, PayloadType, payload)), k.pem)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for _, a := range []string{alice, bob} {
		if err := doc.For(a); err != nil {
			t.Errorf("For(%s): %v", a, err)
		}
	}
	if err := doc.For(carol); !errors.Is(err, ErrNotForAccount) {
		t.Errorf("For(another member): %v, want ErrNotForAccount", err)
	}
	if err := doc.For(""); !errors.Is(err, ErrNotForAccount) {
		t.Errorf("For(no account): %v, want ErrNotForAccount", err)
	}
	if strings.Contains(string(payload), alice) || strings.Contains(string(payload), bob) {
		t.Error("the payload carries an account id in clear")
	}
}

// A document every member receives alike applies to any account.
func TestAnUnboundDocumentAppliesToAnyAccount(t *testing.T) {
	if err := validDoc().For(carol); err != nil {
		t.Fatal(err)
	}
}

// Two bindings of the same accounts draw different salts, so a digest
// identifies an account only within its own document.
func TestEachBindingDrawsItsOwnSalt(t *testing.T) {
	a, _ := BindMembers([]string{alice})
	b, _ := BindMembers([]string{alice})
	if a.Salt == b.Salt || a.Digests[0] == b.Digests[0] {
		t.Fatalf("two bindings share a salt or a digest: %+v %+v", a, b)
	}
	if !a.Includes(alice) || !b.Includes(alice) {
		t.Fatal("a binding does not include its account")
	}
}

func TestBindMembersRefusesNoneAndEmpty(t *testing.T) {
	if _, err := BindMembers(nil); err == nil {
		t.Error("no members was accepted")
	}
	if _, err := BindMembers([]string{alice, ""}); err == nil {
		t.Error("an empty account id was accepted")
	}
	m, err := BindMembers([]string{alice, alice, bob})
	if err != nil || len(m.Digests) != 2 {
		t.Fatalf("repeats: %+v, %v", m, err)
	}
}

// The schema and the members go together, and a binding has its shape.
func TestValidateHoldsTheSchemaToItsMembers(t *testing.T) {
	cases := map[string]func(d *Document){
		"members under the first schema":    func(d *Document) { d.Schema = Schema },
		"the second schema without members": func(d *Document) { d.Members = nil },
		"a short salt":                      func(d *Document) { d.Members.Salt = "AAAA" },
		"no digests":                        func(d *Document) { d.Members.Digests = nil },
		"an unsorted list": func(d *Document) {
			d.Members.Digests = []string{"ffffffffffffffffffffffffffffffff", "00000000000000000000000000000000"}
		},
		"a repeated digest": func(d *Document) {
			d.Members.Digests = []string{"00000000000000000000000000000000", "00000000000000000000000000000000"}
		},
		"an uppercase digest": func(d *Document) { d.Members.Digests = []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} },
		"a long digest":       func(d *Document) { d.Members.Digests = []string{strings.Repeat("0", 64)} },
	}
	for name, mutate := range cases {
		d := boundDoc(t, alice)
		mutate(&d)
		if err := d.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := boundDoc(t, alice, bob, carol).Validate(); err != nil {
		t.Errorf("a valid bound document: %v", err)
	}
}
