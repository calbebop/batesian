package cli

import (
	"net/url"
	"strings"

	attackpkg "github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/report"
)

type outputRedactor struct {
	target   string
	display  string
	userinfo string
	query    string
}

func newOutputRedactor(target string) outputRedactor {
	r := outputRedactor{target: target, display: attackpkg.RedactURL(target)}
	if u, err := url.Parse(target); err == nil {
		if u.User != nil {
			r.userinfo = u.User.String() + "@"
		}
		r.query = u.RawQuery
	}
	return r
}

func (r outputRedactor) url(raw string) string {
	if raw == "" {
		return ""
	}
	return attackpkg.RedactURL(raw)
}

func (r outputRedactor) text(s string) string {
	if r.target != "" {
		s = strings.ReplaceAll(s, r.target, r.display)
	}
	if r.userinfo != "" {
		s = strings.ReplaceAll(s, r.userinfo, "")
	}
	if r.query != "" {
		s = strings.ReplaceAll(s, "?"+r.query, "?REDACTED")
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
			f := &out[i].Findings[j]
			f.Title = r.text(f.Title)
			f.Description = r.text(f.Description)
			f.Evidence = r.text(f.Evidence)
			f.Remediation = r.text(f.Remediation)
			f.TargetURL = r.url(f.TargetURL)
			f.Chain = append([]attackpkg.ChainStep(nil), f.Chain...)
			for k := range f.Chain {
				f.Chain[k].Action = r.text(f.Chain[k].Action)
				f.Chain[k].Outcome = r.text(f.Chain[k].Outcome)
			}
		}
	}
	return out
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
	p.Provider = r.text(p.Provider)
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
