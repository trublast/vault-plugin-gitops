package gitops

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-git/go-billy/v6"
	"gopkg.in/yaml.v3"
)

// collectYAMLPaths returns paths of all .yaml and .yml files under dir (recursive), sorted.
func collectYAMLPaths(dir string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	return paths, nil
}

// parseYAMLDocuments decodes multi-document YAML from data into resources (skips empty docs, normalizes).
func parseYAMLDocuments(data []byte) ([]Resource, error) {
	var resources []Resource
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(false)
	for {
		var doc Resource
		if err := dec.Decode(&doc); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if doc.Path == "" && doc.Data == nil && len(doc.Dependencies) == 0 && doc.Namespace == "" {
			continue
		}
		if doc.Data != nil && !isObject(doc.Data) {
			return nil, fmt.Errorf("document %d: 'data' must be an object (map)", len(resources)+1)
		}
		NormalizeResource(&doc)
		resources = append(resources, doc)
	}
	return resources, nil
}

// parseResourceFiles sorts file paths and parses YAML documents from each into resources.
func parseResourceFiles(fileContents map[string][]byte) ([]Resource, error) {
	paths := make([]string, 0, len(fileContents))
	for p := range fileContents {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var resources []Resource
	for _, fpath := range paths {
		docs, err := parseYAMLDocuments(fileContents[fpath])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", fpath, err)
		}
		resources = append(resources, docs...)
	}
	return resources, nil
}

// LoadResourcesFromPath loads resources from a file or directory.
// If path is a directory, all .yaml and .yml files under it (recursive) are collected and parsed.
// If path is a file, that file is read. Returns parsed and normalized resources.
func LoadResourcesFromPath(path string) ([]Resource, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	var files []string
	if info.IsDir() {
		files, err = collectYAMLPaths(path)
		if err != nil {
			return nil, fmt.Errorf("collect yaml in %s: %w", path, err)
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("no .yaml or .yml files in %s", path)
		}
	} else {
		files = []string{path}
	}

	fileContents := make(map[string][]byte, len(files))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f, err)
		}
		fileContents[f] = data
	}
	return parseResourceFiles(fileContents)
}

// LoadResourcesFromFS extracts .yaml/.yml files from the given filesystem under rootPath and parses them into resources.
func LoadResourcesFromFS(worktreeFS billy.Filesystem, rootPath string) ([]Resource, error) {
	fileContents := make(map[string][]byte)
	normalizedPath := filepath.Clean(rootPath)
	if normalizedPath == "." {
		normalizedPath = ""
	}

	var walk func(dir string) error
	walk = func(dir string) error {
		entries, err := worktreeFS.ReadDir(dir)
		if err != nil {
			return fmt.Errorf("reading directory %q: %w", dir, err)
		}
		for _, entry := range entries {
			filePath := path.Join(dir, entry.Name())
			if entry.IsDir() {
				if err := walk(filePath); err != nil {
					return err
				}
				continue
			}
			info, err := entry.Info()
			if err != nil {
				return fmt.Errorf("file info for %q: %w", filePath, err)
			}
			if info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			ext := strings.ToLower(path.Ext(entry.Name()))
			if ext != ".yaml" && ext != ".yml" {
				continue
			}
			normalizedFilePath := filepath.Clean(filePath)
			if normalizedPath != "" {
				if normalizedFilePath != normalizedPath && !strings.HasPrefix(normalizedFilePath, normalizedPath+string(filepath.Separator)) {
					continue
				}
			}
			f, err := worktreeFS.Open(filePath)
			if err != nil {
				return fmt.Errorf("opening %q: %w", filePath, err)
			}
			data, err := io.ReadAll(f)
			f.Close()
			if err != nil {
				return fmt.Errorf("reading %q: %w", filePath, err)
			}
			fileContents[filePath] = data
		}
		return nil
	}

	if err := walk(""); err != nil {
		return nil, err
	}
	return parseResourceFiles(fileContents)
}
