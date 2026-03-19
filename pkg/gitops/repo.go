package gitops

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-git/go-git/v6"

	trdlGit "github.com/trublast/vault-plugin-gitops/pkg/git"
)

// LoadResourcesFromRepo extracts .yaml/.yml files from git repository under rootPath and parses them into resources.
func LoadResourcesFromRepo(gitRepo *git.Repository, rootPath string) ([]Resource, error) {
	fileContents := make(map[string][]byte)
	normalizedPath := filepath.Clean(rootPath)
	if normalizedPath == "." {
		normalizedPath = ""
	}

	err := trdlGit.ForEachWorktreeFile(gitRepo, func(filePath, link string, fileReader io.Reader, info os.FileInfo) error {
		if info.IsDir() || link != "" || fileReader == nil {
			return nil
		}
		base := path.Base(filePath)
		ext := strings.ToLower(path.Ext(base))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		normalizedFilePath := filepath.Clean(filePath)
		if normalizedPath != "" {
			if normalizedFilePath != normalizedPath && !strings.HasPrefix(normalizedFilePath, normalizedPath+string(filepath.Separator)) {
				return nil
			}
		}
		data, err := io.ReadAll(fileReader)
		if err != nil {
			return err
		}
		fileContents[filePath] = data
		return nil
	})
	if err != nil {
		return nil, err
	}

	var paths []string
	for p := range fileContents {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var resources []Resource
	for _, fpath := range paths {
		data := fileContents[fpath]
		docs, err := parseYAMLDocuments(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", fpath, err)
		}
		resources = append(resources, docs...)
	}

	return resources, nil
}
