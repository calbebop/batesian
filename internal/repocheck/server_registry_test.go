package repocheck

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestTestdataReadmeServerRegistryUniquePorts fails if testdata/README.md Server
// Registry assigns the same port to more than one server file.
func TestTestdataReadmeServerRegistryUniquePorts(t *testing.T) {
	t.Helper()
	readme := readTestdataREADME(t)
	// Markdown table rows: | `server.py` | <port> | ...
	row := regexp.MustCompile(`(?m)^\|\s*` + "`([^`]+)`" + `\s*\|\s*(\d+)\s*\|`)
	byPort := make(map[int][]string)
	for _, m := range row.FindAllStringSubmatch(string(readme), -1) {
		file := strings.TrimSpace(m[1])
		port, err := strconv.Atoi(strings.TrimSpace(m[2]))
		if err != nil {
			t.Fatalf("parse port %q: %v", m[2], err)
		}
		if !strings.HasSuffix(file, ".py") {
			continue
		}
		byPort[port] = append(byPort[port], file)
	}
	var dups []string
	for port, files := range byPort {
		if len(files) > 1 {
			dups = append(dups, strconv.Itoa(port)+": "+strings.Join(files, ", "))
		}
	}
	if len(dups) > 0 {
		t.Fatalf("duplicate ports in testdata/README.md Server Registry:\n%s", strings.Join(dups, "\n"))
	}
}

func readTestdataREADME(t *testing.T) []byte {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	p := filepath.Join(repoRoot, "testdata", "README.md")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return b
}
