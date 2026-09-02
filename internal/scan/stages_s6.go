package scan

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// S6 — Capability consistency (§8.3). For code-bearing kinds, detect network
// calls, subprocess/exec, filesystem access, env reads, and dynamic
// evaluation in JS/TS and Python, map detections to the capability
// vocabulary, and diff against the manifest's declared capabilities.
// Undeclared network/exec/fs-write is high (§8.3). Native regex detectors
// stand in for opengrep rulepacks (DEV-006) behind the same stage.
type S6Capabilities struct {
	// Opengrep, when set, execs the real tool against its rules and merges
	// the detections into the declared-vs-detected compare (DEV-006
	// production upgrade, agentry#40).
	Opengrep *ExecTool
}

func (S6Capabilities) ID() string { return "S6" }

// capDetector maps a source pattern to a capability token.
type capDetector struct {
	cap string
	re  *regexp.Regexp
}

var jsDetectors = []capDetector{
	{"network", regexp.MustCompile(`\b(?:fetch|XMLHttpRequest|WebSocket)\s*\(`)},
	{"network", regexp.MustCompile(`require\(\s*['"](?:https?|net|http2|dgram|axios|node-fetch|got|undici)['"]\s*\)`)},
	{"network", regexp.MustCompile(`\bimport\b[^;\n]*['"](?:https?|node:net|node:http|axios|node-fetch|got|undici)['"]`)},
	{"exec", regexp.MustCompile(`require\(\s*['"](?:child_process|node:child_process)['"]\s*\)`)},
	{"exec", regexp.MustCompile(`\b(?:execSync|execFileSync|spawnSync|exec|spawn|execFile)\s*\(`)},
	{"fs-write", regexp.MustCompile(`\b(?:writeFileSync|writeFile|appendFileSync|createWriteStream|rmSync|unlinkSync|mkdirSync)\s*\(`)},
	{"fs-read", regexp.MustCompile(`\b(?:readFileSync|readFile|createReadStream|readdirSync)\s*\(`)},
	{"env", regexp.MustCompile(`\bprocess\.env\b`)},
	{"eval", regexp.MustCompile(`\b(?:eval|Function)\s*\(|new\s+Function\s*\(`)},
	{"eval", regexp.MustCompile(`\bimport\s*\(`)}, // dynamic import
}

var pyDetectors = []capDetector{
	{"network", regexp.MustCompile(`\bimport\s+(?:requests|httpx|urllib|urllib2|http\.client|socket|aiohttp)\b`)},
	{"network", regexp.MustCompile(`\bfrom\s+(?:urllib|http|requests|httpx|aiohttp)\b`)},
	{"exec", regexp.MustCompile(`\bimport\s+subprocess\b|\bsubprocess\.(?:run|Popen|call|check_output)\s*\(`)},
	{"exec", regexp.MustCompile(`\bos\.(?:system|popen|exec[lv]?[pe]*)\s*\(`)},
	{"fs-write", regexp.MustCompile(`\bopen\s*\([^)]*['"][wax]\+?b?['"]`)},
	{"fs-write", regexp.MustCompile(`\b(?:os\.remove|os\.unlink|shutil\.rmtree|os\.mkdir)\s*\(`)},
	{"env", regexp.MustCompile(`\bos\.environ\b|\bos\.getenv\s*\(`)},
	{"eval", regexp.MustCompile(`\b(?:eval|exec|compile|__import__)\s*\(`)},
}

func (s S6Capabilities) Run(sc stageContext, in *Input) StageResult {
	if in.Kind != "mcp-server" {
		return StageResult{Scanner: "S6"} // only code kinds carry code (§1.4)
	}
	declared := declaredCaps(in.ManifestJSON)
	detected := map[string][]detection{}

	for _, f := range in.Files {
		if !f.IsText || f.Content == nil {
			continue
		}
		var dets []capDetector
		switch strings.ToLower(filepath.Ext(f.Path)) {
		case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs":
			dets = jsDetectors
		case ".py":
			dets = pyDetectors
		default:
			continue
		}
		lines := strings.Split(string(f.Content), "\n")
		for i, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "//") || strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue // skip obvious comments (best-effort)
			}
			for _, d := range dets {
				if d.re.MatchString(line) {
					detected[d.cap] = append(detected[d.cap], detection{file: f.Path, line: i + 1})
				}
			}
		}
	}

	var findings []Finding
	if s.Opengrep != nil && in.Dir != "" {
		extra, dets := runOpengrep(sc.Context(), s.Opengrep, in.Dir)
		findings = append(findings, extra...)
		for capToken, hits := range dets {
			detected[capToken] = append(detected[capToken], hits...)
		}
	}
	// Undeclared capabilities are the security event (§8.3). Iterated in a
	// fixed order because the report is hashed and signed (§8.8).
	detectedTokens := make([]string, 0, len(detected))
	for capToken := range detected {
		detectedTokens = append(detectedTokens, capToken)
	}
	sort.Strings(detectedTokens)
	for _, capToken := range detectedTokens {
		hits := detected[capToken]
		if declaredHas(declared, capToken) {
			continue
		}
		sev := SevMedium
		conf := ConfMedium
		switch capToken {
		case "network", "exec", "fs-write":
			sev = SevHigh
		case "eval":
			sev = SevHigh
			conf = ConfLow // eval detection is noisier
		}
		h := hits[0]
		findings = append(findings, Finding{
			Scanner: "S6/undeclared-" + capToken, Severity: sev, Confidence: conf,
			Title:    "Undeclared capability: " + capToken,
			FilePath: h.file, LineStart: h.line, LineEnd: h.line,
			Detail:   map[string]any{"capability": capToken, "occurrences": len(hits)},
			Taxonomy: []string{"LLM03", "ASI04"},
		})
	}
	findings = append(findings, s6DeclaredUnused(declared, detected)...)
	findings = append(findings, s6StringAssembly(in)...)
	return StageResult{Scanner: "S6", Findings: findings}
}

type detection struct {
	file string
	line int
}

// declaredCaps extracts a flat capability-token set from the manifest JSON.
func declaredCaps(manifestJSON []byte) map[string]bool {
	out := map[string]bool{}
	var m struct {
		Capabilities struct {
			Network struct {
				Egress []string `json:"egress"`
			} `json:"network"`
			Filesystem struct {
				Read  json.RawMessage `json:"read"`
				Write json.RawMessage `json:"write"`
			} `json:"filesystem"`
			Exec    json.RawMessage `json:"exec"`
			Secrets []string        `json:"secrets"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		return out
	}
	if len(m.Capabilities.Network.Egress) > 0 && !onlyNone(m.Capabilities.Network.Egress) {
		out["network"] = true
	}
	if notNone(m.Capabilities.Filesystem.Write) {
		out["fs-write"] = true
	}
	if notNone(m.Capabilities.Filesystem.Read) {
		out["fs-read"] = true
	}
	if notNone(m.Capabilities.Exec) {
		out["exec"] = true
	}
	if len(m.Capabilities.Secrets) > 0 {
		out["env"] = true
	}
	return out
}

func declaredHas(declared map[string]bool, capToken string) bool {
	switch capToken {
	case "eval":
		// eval/dynamic-import has no manifest vocabulary; it is always a
		// flag when present in code (obfuscation indicator, §8.3 S6).
		return false
	case "fs-read":
		return declared["fs-read"] || declared["fs-write"]
	default:
		return declared[capToken]
	}
}

func onlyNone(egress []string) bool {
	for _, e := range egress {
		if e != "none" && e != "" {
			return false
		}
	}
	return true
}

// notNone reports whether a filesystem/exec JSON value declares more than
// "none" (string "none" → false; object/list → true).
func notNone(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s != "none" && s != ""
	}
	return true // object or array form ⇒ a real capability
}
