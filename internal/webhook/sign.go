package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SignatureHeader is the delivery signature header name.
const SignatureHeader = "X-Agentry-Signature"

// MaxSignatureAge is the freshness window a receiver should enforce on the
// timestamp (±5 min). Exposed for the receiver-side Verify used in tests
// and by any first-party consumer.
const MaxSignatureAge = 5 * time.Minute

// Sign returns the value for X-Agentry-Signature over the payload at time ts:
//
//	t=<unix>,v1=<hex(HMAC_SHA256(secret, "<unix>.<body>"))>
//
// Binding the timestamp into the signed material (the "<t>.<body>" scheme, as
// used by Stripe/GitHub) stops a captured (t, signature) pair from being
// replayed with a fresh timestamp.
func Sign(secret, body []byte, ts time.Time) string {
	t := ts.Unix()
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(strconv.FormatInt(t, 10) + "."))
	mac.Write(body)
	return fmt.Sprintf("t=%d,v1=%s", t, hex.EncodeToString(mac.Sum(nil)))
}

// Verify checks a signature header against the body: the timestamp must be
// within MaxSignatureAge of now and the v1 HMAC must match (constant-time).
// First-party/receiver helper — the sender only calls Sign.
func Verify(secret, body []byte, header string, now time.Time) error {
	ts, v1, err := parseSignatureHeader(header)
	if err != nil {
		return err
	}
	age := now.Sub(time.Unix(ts, 0))
	if age < 0 {
		age = -age
	}
	if age > MaxSignatureAge {
		return fmt.Errorf("webhook: signature timestamp outside ±%s window", MaxSignatureAge)
	}
	expected := Sign(secret, body, time.Unix(ts, 0))
	_, expV1, _ := parseSignatureHeader(expected)
	if !hmac.Equal([]byte(v1), []byte(expV1)) {
		return fmt.Errorf("webhook: signature mismatch")
	}
	return nil
}

func parseSignatureHeader(header string) (ts int64, v1 string, err error) {
	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			ts, err = strconv.ParseInt(kv[1], 10, 64)
			if err != nil {
				return 0, "", fmt.Errorf("webhook: bad timestamp in signature: %w", err)
			}
		case "v1":
			v1 = kv[1]
		}
	}
	if ts == 0 || v1 == "" {
		return 0, "", fmt.Errorf("webhook: malformed signature header")
	}
	return ts, v1, nil
}
