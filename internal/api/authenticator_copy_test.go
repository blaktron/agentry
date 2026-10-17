package api

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// What a sign-in provider enrols (a TOTP app, a security key) is an
// *authenticator*; a *device* in this estate is a remembered browser, the
// credential that skips the second factor. The account page must not show
// "devices" with two meanings. This keeps its prose from drifting back.

var (
	deviceWordRe       = regexp.MustCompile(`(?i)\bdevices?\b`)
	rememberedDeviceRe = regexp.MustCompile(`(?i)\bremembered devices?\b`)
)

func TestEnrolledAuthenticatorProseSaysAuthenticator(t *testing.T) {
	page, err := os.ReadFile("../ui/templates/account.html")
	if err != nil {
		t.Fatal(err)
	}
	// What a reader sees or hears: the text between tags, and the labels
	// inside them. A remembered device is the right word for that
	// credential, should the page ever list them.
	html := regexp.MustCompile(`\{\{.*?\}\}`).ReplaceAllString(string(page), " ")
	var heard []string
	for _, m := range regexp.MustCompile(`(?:title|aria-label|placeholder)="([^"]*)"`).FindAllStringSubmatch(html, -1) {
		heard = append(heard, m[1])
	}
	text := regexp.MustCompile(`<[^>]*>`).ReplaceAllString(html, "\n")
	for _, line := range append(strings.Split(text, "\n"), heard...) {
		if deviceWordRe.MatchString(rememberedDeviceRe.ReplaceAllString(line, "")) {
			t.Errorf("the account page says device for an authenticator: %q", strings.TrimSpace(line))
		}
	}
}
