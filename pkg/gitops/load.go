package gitops

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

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

	var resources []Resource
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f, err)
		}
		docs, err := parseYAMLDocuments(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		resources = append(resources, docs...)
	}
	return resources, nil
}
