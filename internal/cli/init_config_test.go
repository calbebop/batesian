package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/config"
)

func TestInitCreatesConfigWithoutOverwriting(t *testing.T) {
	t.Chdir(t.TempDir())
	output, err := captureCLIOutput(t, func() error { return runInitConfig(initConfigCmd, nil) })
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if !strings.Contains(output, "Created batesian.yaml") || strings.Contains(output, "# batesian.yaml") {
		t.Fatalf("unexpected stdout: %q", output)
	}
	data, err := os.ReadFile("batesian.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != config.Example() {
		t.Fatal("init wrote an incomplete config")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat("batesian.yaml")
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("config permissions = %o, want 600", got)
		}
	}
	if err := runInitConfig(initConfigCmd, nil); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second init error = %v, want already exists", err)
	}
	again, err := os.ReadFile("batesian.yaml")
	if err != nil || string(again) != string(data) {
		t.Fatalf("existing config changed: %v", err)
	}
}

func TestInitRejectsDanglingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires additional privileges on Windows")
	}
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Symlink("other.yaml", "batesian.yaml"); err != nil {
		t.Fatal(err)
	}
	if err := runInitConfig(initConfigCmd, nil); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("init error = %v, want already exists", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "other.yaml")); !os.IsNotExist(err) {
		t.Fatalf("symlink target was created: %v", err)
	}
	if info, err := os.Lstat("batesian.yaml"); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("existing symlink changed: %v", err)
	}
}

func TestInitConcurrentCreate(t *testing.T) {
	t.Chdir(t.TempDir())
	const attempts = 12
	start := make(chan struct{})
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- runInitConfig(initConfigCmd, nil)
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("unexpected init error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful creates = %d, want 1", successes)
	}
	data, err := os.ReadFile("batesian.yaml")
	if err != nil || string(data) != config.Example() {
		t.Fatalf("concurrent init wrote an incomplete config: %v", err)
	}
}
