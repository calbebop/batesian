package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// maxRuleFileBytes is the maximum size of a single rule YAML file. Files larger
// than this are skipped with a warning to prevent accidental large-file DoS.
const maxRuleFileBytes = 4 * 1024 * 1024 // 4 MiB

// LoadDir loads all .yaml and .yml rule files from dir and its subdirectories.
// Files that fail to parse or validate are collected as warnings, not fatal errors,
// so a single bad rule file does not block the scan.
func LoadDir(dir string) ([]*Rule, []LoadWarning, error) {
	return loadFS(os.DirFS(dir), ".")
}

// LoadFS loads all .yaml and .yml rule files from an fs.FS.
// Used to load the built-in rules from the embedded filesystem.
func LoadFS(fsys fs.FS) ([]*Rule, []LoadWarning, error) {
	return loadFS(fsys, ".")
}

// LoadWarning records a non-fatal error encountered while loading rules.
type LoadWarning struct {
	Path string
	Err  error
}

// Filter holds criteria for selecting a subset of loaded rules.
type Filter struct {
	Protocols  []string // empty = all
	Severities []string // empty = all
	Tags       []string // empty = all
	IDs        []string // empty = all
}

// Apply returns the subset of rules that match the filter.
func (f *Filter) Apply(rules []*Rule) []*Rule {
	if f == nil {
		return rules
	}
	var out []*Rule
	for _, r := range rules {
		if f.matchesProtocol(r) && f.matchesSeverity(r) && f.matchesTags(r) && f.matchesID(r) {
			out = append(out, r)
		}
	}
	return out
}

func (f *Filter) matchesProtocol(r *Rule) bool {
	if len(f.Protocols) == 0 {
		return true
	}
	for _, p := range f.Protocols {
		if strings.EqualFold(r.Attack.Protocol, p) {
			return true
		}
	}
	return false
}

func (f *Filter) matchesSeverity(r *Rule) bool {
	if len(f.Severities) == 0 {
		return true
	}
	for _, s := range f.Severities {
		if strings.EqualFold(r.Info.Severity, s) {
			return true
		}
	}
	return false
}

func (f *Filter) matchesTags(r *Rule) bool {
	if len(f.Tags) == 0 {
		return true
	}
	for _, want := range f.Tags {
		for _, have := range r.Info.Tags {
			if strings.EqualFold(have, want) {
				return true
			}
		}
	}
	return false
}

func (f *Filter) matchesID(r *Rule) bool {
	if len(f.IDs) == 0 {
		return true
	}
	for _, id := range f.IDs {
		if strings.EqualFold(r.ID, id) {
			return true
		}
	}
	return false
}

// loadFS walks fsys starting at root and loads all YAML rule files.
func loadFS(fsys fs.FS, root string) ([]*Rule, []LoadWarning, error) {
	var rules []*Rule
	var warns []LoadWarning

	err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		info, statErr := fs.Stat(fsys, path)
		if statErr == nil && info.Size() > maxRuleFileBytes {
			warns = append(warns, LoadWarning{Path: path, Err: fmt.Errorf("rule file too large (%d bytes, max %d)", info.Size(), maxRuleFileBytes)})
			return nil
		}

		data, readErr := fs.ReadFile(fsys, path)
		if readErr != nil {
			warns = append(warns, LoadWarning{Path: path, Err: readErr})
			return nil
		}

		rule, parseErr := parseRule(data, path)
		if parseErr != nil {
			warns = append(warns, LoadWarning{Path: path, Err: parseErr})
			return nil
		}

		rules = append(rules, rule)
		return nil
	})
	if err != nil {
		return nil, warns, fmt.Errorf("walking rule directory: %w", err)
	}
	return rules, warns, nil
}

// parseRule decodes and validates a single rule from YAML bytes.
func parseRule(data []byte, path string) (*Rule, error) {
	var rule Rule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("parsing YAML in %s: %w", path, err)
	}
	if err := rule.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &rule, nil
}
