package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/trublast/vault-plugin-gitops/pkg/gitops"
)

// fileStateWriter saves state to a file on each SaveState.
type fileStateWriter struct {
	filename string
}

func (w fileStateWriter) SaveState(ctx context.Context, state *gitops.State) error {
	if state == nil || w.filename == "" {
		return nil
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(w.filename, data, 0600)
}

func loadStateFromFile(filename string) (*gitops.State, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return &gitops.State{Resources: make(map[string]gitops.StateResource)}, nil
		}
		return nil, err
	}
	var state gitops.State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	if state.Resources == nil {
		state.Resources = make(map[string]gitops.StateResource)
	}
	return &state, nil
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	cmd := strings.ToLower(os.Args[1])

	if cmd == "lint" {
		if len(os.Args) != 3 {
			printUsage()
			os.Exit(1)
		}
		path := os.Args[2]
		runLint(path)
		return
	}

	if cmd == "test" {
		fs := flag.NewFlagSet("test", flag.ExitOnError)
		stateFile := fs.String("state", "", "load and save state to file")
		_ = fs.Parse(os.Args[2:])
		path := fs.Arg(0)
		if path == "" {
			printUsage()
			os.Exit(1)
		}
		runTest(path, *stateFile)
		return
	}

	fmt.Fprintf(os.Stderr, "unknown command %q; use lint or test\n", cmd)
	printUsage()
	os.Exit(1)
}

func runLint(path string) {
	resources, err := gitops.LoadResourcesFromPath(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load: %v\n", err)
		os.Exit(1)
	}
	if err := gitops.Lint(resources); err != nil {
		fmt.Fprintf(os.Stderr, "lint: %v\n", err)
		os.Exit(1)
	}
}

func runTest(path, stateFile string) {
	resources, err := gitops.LoadResourcesFromPath(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load: %v\n", err)
		os.Exit(1)
	}
	if err := gitops.Lint(resources); err != nil {
		fmt.Fprintf(os.Stderr, "lint: %v\n", err)
		os.Exit(1)
	}

	token := strings.TrimSpace(os.Getenv("VAULT_TOKEN"))
	if token == "" {
		fmt.Fprintln(os.Stderr, "test requires VAULT_TOKEN to be set")
		os.Exit(1)
	}
	cfg := api.DefaultConfig()
	if err := cfg.ReadEnvironment(); err != nil {
		fmt.Fprintf(os.Stderr, "test (vault config): %v\n", err)
		os.Exit(1)
	}
	vaultClient, err := api.NewClient(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "test (vault client): %v\n", err)
		os.Exit(1)
	}

	var state *gitops.State
	if stateFile != "" {
		var err error
		state, err = loadStateFromFile(stateFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "test (load state): %v\n", err)
			os.Exit(1)
		}
	} else {
		state = &gitops.State{Resources: make(map[string]gitops.StateResource)}
	}
	if state.Resources == nil {
		state.Resources = make(map[string]gitops.StateResource)
	}

	var writer gitops.StateWriter
	if stateFile != "" {
		writer = fileStateWriter{filename: stateFile}
	}
	if err := gitops.Apply(context.Background(), resources, vaultClient, state, writer); err != nil {
		fmt.Fprintf(os.Stderr, "test (apply): %v\n", err)
		os.Exit(1)
	}
	if writer != nil {
		if err := writer.SaveState(context.Background(), state); err != nil {
			fmt.Fprintf(os.Stderr, "test (save state): %v\n", err)
			os.Exit(1)
		}
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "usage: gitops-tool lint <path>")
	fmt.Fprintln(os.Stderr, "       gitops-tool test [-state <file>] <path>")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  lint: validate declarative YAML (path, data, names, dependencies).")
	fmt.Fprintln(os.Stderr, "  test: run apply against Vault; requires VAULT_ADDR and VAULT_TOKEN.")
	fmt.Fprintln(os.Stderr, "        -state: optional file to load state from and save state to.")
	fmt.Fprintln(os.Stderr, "  path: file (.yaml/.yml) or directory (recursively collects .yaml/.yml)")
}
