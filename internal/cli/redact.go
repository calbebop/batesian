package cli

import (
	"net/url"
	"sort"
	"strings"

	attackpkg "github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/report"
)

type outputRedactor struct {
	display string
	urls    []redactedURL
	secrets []string
}

type redactedURL struct {
	raw      string
	display  string
	userinfo string
	query    string
}

func newOutputRedactor(target string) outputRedactor {
	r := outputRedactor{display: attackpkg.RedactURL(target)}
	r.addURL(target)
	return r
}

func (r *outputRedactor) addURL(raw string) {
	if raw == "" {
		return
	}
	entry := redactedURL{raw: raw, display: attackpkg.RedactURL(raw)}
	candidate := raw
	if !strings.Contains(raw, "://") && strings.Contains(raw, "@") {
		candidate = "http://" + raw
	}
	if u, err := url.Parse(candidate); err == nil {
		if u.User != nil {
			entry.userinfo = u.User.String() + "@"
			if password, ok := u.User.Password(); ok {
				r.addSecret(password)
			}
		}
		entry.query = u.RawQuery
	}
	r.urls = append(r.urls, entry)
	sort.SliceStable(r.urls, func(i, j int) bool {
		return len(r.urls[i].raw) > len(r.urls[j].raw)
	})
}

func (r *outputRedactor) addSecret(secret string) {
	if secret == "" {
		return
	}
	r.secrets = append(r.secrets, secret)
	sort.SliceStable(r.secrets, func(i, j int) bool {
		return len(r.secrets[i]) > len(r.secrets[j])
	})
}

func (r outputRedactor) displayTarget() string {
	return r.text(r.display)
}

func credentialHeader(name string) bool {
	name = strings.ToLower(name)
	if name == "authorization" || name == "proxy-authorization" || name == "cookie" || name == "key" ||
		strings.HasPrefix(name, "x-auth") || strings.HasSuffix(name, "-key") {
		return true
	}
	for _, part := range []string{"token", "secret", "credential"} {
		if strings.Contains(name, part) {
			return true
		}
	}
	return false
}

func (r outputRedactor) url(raw string) string {
	if raw == "" {
		return ""
	}
	return r.text(attackpkg.RedactURL(raw))
}

func (r outputRedactor) text(s string) string {
	for _, entry := range r.urls {
		s = strings.ReplaceAll(s, entry.raw, entry.display)
	}
	for _, entry := range r.urls {
		if entry.userinfo != "" {
			s = strings.ReplaceAll(s, entry.userinfo, "")
		}
		if entry.query != "" {
			s = strings.ReplaceAll(s, "?"+entry.query, "?REDACTED")
		}
	}
	for _, secret := range r.secrets {
		s = strings.ReplaceAll(s, secret, "<redacted>")
	}
	return s
}

type redactedError struct {
	err  error
	text string
}

func (e redactedError) Error() string { return e.text }
func (e redactedError) Unwrap() error { return e.err }

func (r outputRedactor) err(err error) error {
	if err == nil {
		return nil
	}
	text := r.text(err.Error())
	if text == err.Error() {
		return err
	}
	return redactedError{err: err, text: text}
}

func (r outputRedactor) results(results []engine.RunResult) []engine.RunResult {
	out := make([]engine.RunResult, len(results))
	copy(out, results)
	for i := range out {
		out[i].SkipMsg = r.text(out[i].SkipMsg)
		if out[i].Err != nil {
			out[i].Err = r.err(out[i].Err)
		}
		out[i].Findings = append([]attackpkg.Finding(nil), results[i].Findings...)
		for j := range out[i].Findings {
			out[i].Findings[j] = r.finding(out[i].Findings[j])
		}
	}
	return out
}

func (r outputRedactor) finding(f attackpkg.Finding) attackpkg.Finding {
	f.Title = r.text(f.Title)
	f.Description = r.text(f.Description)
	f.Evidence = r.text(f.Evidence)
	f.Remediation = r.text(f.Remediation)
	f.TargetURL = r.url(f.TargetURL)
	f.Chain = append([]attackpkg.ChainStep(nil), f.Chain...)
	for i := range f.Chain {
		f.Chain[i].Principal = r.text(f.Chain[i].Principal)
		f.Chain[i].Action = r.text(f.Chain[i].Action)
		f.Chain[i].Outcome = r.text(f.Chain[i].Outcome)
	}
	f.Related = append([]attackpkg.Finding(nil), f.Related...)
	for i := range f.Related {
		f.Related[i] = r.finding(f.Related[i])
	}
	return f
}

func (r outputRedactor) value(v any) any {
	switch v := v.(type) {
	case string:
		if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
			return r.url(v)
		}
		return r.text(v)
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[k] = r.value(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = r.value(item)
		}
		return out
	default:
		return v
	}
}

func (r outputRedactor) a2aProbeResult(p *report.ProbeResult) {
	p.Name = r.text(p.Name)
	p.Description = r.text(p.Description)
	p.URL = r.url(p.URL)
	p.Version = r.text(p.Version)
	p.Provider = r.text(p.Provider)
	p.ProtocolVersion = r.text(p.ProtocolVersion)
	for i := range p.SecuritySchemes {
		p.SecuritySchemes[i] = r.text(p.SecuritySchemes[i])
	}
	for i := range p.Skills {
		p.Skills[i].ID = r.text(p.Skills[i].ID)
		p.Skills[i].Name = r.text(p.Skills[i].Name)
		p.Skills[i].Description = r.text(p.Skills[i].Description)
		for j := range p.Skills[i].Tags {
			p.Skills[i].Tags[j] = r.text(p.Skills[i].Tags[j])
		}
	}
	for i := range p.Flags {
		p.Flags[i].Message = r.text(p.Flags[i].Message)
	}
}

func (r outputRedactor) mcpProbeResult(p *report.MCPProbeResult) {
	p.ServerName = r.text(p.ServerName)
	p.ServerVersion = r.text(p.ServerVersion)
	p.ServerTitle = r.text(p.ServerTitle)
	p.URL = r.url(p.URL)
	p.ProtocolVersion = r.text(p.ProtocolVersion)
	for i := range p.Tools {
		p.Tools[i].Name = r.text(p.Tools[i].Name)
		p.Tools[i].Description = r.text(p.Tools[i].Description)
	}
	for i := range p.Resources {
		p.Resources[i].URI = r.text(p.Resources[i].URI)
		p.Resources[i].MimeType = r.text(p.Resources[i].MimeType)
	}
	for i := range p.Prompts {
		p.Prompts[i].Name = r.text(p.Prompts[i].Name)
	}
	for i := range p.Flags {
		p.Flags[i].Message = r.text(p.Flags[i].Message)
	}
}
