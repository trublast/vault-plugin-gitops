package git

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sync/atomic"
	"time"

	"github.com/go-git/go-billy/v6"
	"github.com/go-git/go-billy/v6/memfs"
	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/transport"
	"github.com/go-git/go-git/v6/storage"
	"github.com/go-git/go-git/v6/storage/memory"
)

// ErrCloneSizeLimitExceeded is returned when the repository size exceeds MaxCloneSizeBytes during in-memory clone.
var ErrCloneSizeLimitExceeded = errors.New("clone size limit exceeded")

type CloneOptions struct {
	TagName           string
	BranchName        string
	ReferenceName     string
	RecurseSubmodules git.SubmoduleRecursivity
	Auth              transport.AuthMethod
	CABundle          []byte
	// MaxCloneSizeBytes limits total size of objects stored during in-memory clone (0 = no limit).
	// When exceeded, clone fails with ErrCloneSizeLimitExceeded. Use to prevent OOM on large or malicious repos.
	MaxCloneSizeBytes int64
}

// limitedStorage wraps memory.Storage and fails writes when total size exceeds limit.
type limitedStorage struct {
	*memory.Storage
	limit int64
	used  atomic.Int64
}

// RawObjectWriter checks the declared object size upfront and rejects objects
// that would push total usage over the limit — before any data is streamed.
// This is the primary size-limiting mechanism in go-git v6, where the packfile
// scanner writes object data incrementally through the returned writer.
func (s *limitedStorage) RawObjectWriter(typ plumbing.ObjectType, sz int64) (io.WriteCloser, error) {
	if sz < 0 {
		sz = 0
	}
	newUsed := s.used.Add(sz)
	if s.limit > 0 && newUsed > s.limit {
		s.used.Add(-sz)
		return nil, fmt.Errorf("%w: limit %d bytes", ErrCloneSizeLimitExceeded, s.limit)
	}
	w, err := s.Storage.RawObjectWriter(typ, sz)
	if err != nil {
		s.used.Add(-sz)
		return nil, err
	}
	return w, nil
}

func CloneInMemory(url string, opts CloneOptions) (*git.Repository, error) {
	var storer storage.Storer
	if opts.MaxCloneSizeBytes > 0 {
		storer = &limitedStorage{
			Storage: memory.NewStorage(),
			limit:   opts.MaxCloneSizeBytes,
		}
	} else {
		storer = memory.NewStorage()
	}
	fs := memfs.New()

	cloneOptions := &git.CloneOptions{}
	{
		cloneOptions.URL = url

		switch {
		case opts.TagName != "":
			cloneOptions.ReferenceName = plumbing.ReferenceName(fmt.Sprintf("refs/tags/%s", opts.TagName))
		case opts.BranchName != "":
			cloneOptions.ReferenceName = plumbing.ReferenceName(fmt.Sprintf("refs/heads/%s", opts.BranchName))
		case opts.ReferenceName != "":
			cloneOptions.ReferenceName = plumbing.ReferenceName(opts.ReferenceName)
		}

		if opts.RecurseSubmodules != 0 {
			cloneOptions.RecurseSubmodules = opts.RecurseSubmodules
		}

		if opts.Auth != nil {
			cloneOptions.Auth = opts.Auth
		}

		if len(opts.CABundle) > 0 {
			cloneOptions.CABundle = opts.CABundle
		}
	}

	return git.Clone(storer, fs, cloneOptions)
}

func AddWorktreeFilesToTar(tw *tar.Writer, gitRepo *git.Repository) error {
	return ForEachWorktreeFile(gitRepo, func(path, link string, fileReader io.Reader, info os.FileInfo) error {
		size := info.Size()

		// The size field is the size of the file in bytes; linked files are archived with this field specified as zero
		if link != "" {
			size = 0
		}

		if err := tw.WriteHeader(&tar.Header{
			Format:     tar.FormatGNU,
			Name:       path,
			Linkname:   link,
			Size:       size,
			Mode:       int64(info.Mode()),
			ModTime:    time.Now(),
			AccessTime: time.Now(),
			ChangeTime: time.Now(),
		}); err != nil {
			return fmt.Errorf("unable to write tar entry %q header: %w", path, err)
		}

		if link == "" {
			_, err := io.Copy(tw, fileReader)
			if err != nil {
				return fmt.Errorf("unable to write tar entry %q data: %w", path, err)
			}
		}

		return nil
	})
}

func ForEachWorktreeFile(gitRepo *git.Repository, fileFunc func(path, link string, fileReader io.Reader, info os.FileInfo) error) error {
	w, err := gitRepo.Worktree()
	if err != nil {
		return fmt.Errorf("unable to get git repository worktree: %w", err)
	}
	return ForEachFile(w.Filesystem, fileFunc)
}

// ForEachFile walks all files in the given billy filesystem and calls fileFunc for each.
func ForEachFile(billyFS billy.Filesystem, fileFunc func(path, link string, fileReader io.Reader, info os.FileInfo) error) error {
	var processFilesFunc func(directory string, entries []fs.DirEntry) error
	processFilesFunc = func(directory string, entries []fs.DirEntry) error {
		for _, entry := range entries {
			absPath := path.Join(directory, entry.Name())
			if entry.IsDir() {
				subEntries, err := billyFS.ReadDir(absPath)
				if err != nil {
					return fmt.Errorf("unable to read dir %q: %w", absPath, err)
				}

				if err := processFilesFunc(absPath, subEntries); err != nil {
					return err
				}

				continue
			}

			fileInfo, err := entry.Info()
			if err != nil {
				return fmt.Errorf("unable to get file info for %q: %w", absPath, err)
			}

			if fileInfo.Mode()&os.ModeSymlink == os.ModeSymlink {
				link, err := billyFS.Readlink(absPath)
				if err != nil {
					return fmt.Errorf("unable to read link %q: %w", absPath, err)
				}

				if err := fileFunc(absPath, link, nil, fileInfo); err != nil {
					return err
				}
			} else {
				billyFile, err := billyFS.Open(absPath)
				if err != nil {
					return fmt.Errorf("unable to open file %q: %w", absPath, err)
				}

				if err := fileFunc(absPath, "", billyFile, fileInfo); err != nil {
					return err
				}

				if err := billyFile.Close(); err != nil {
					return err
				}
			}
		}

		return nil
	}

	rootDirectory := ""
	files, err := billyFS.ReadDir(rootDirectory)
	if err != nil {
		return fmt.Errorf("unable to read root directory: %w", err)
	}

	return processFilesFunc(rootDirectory, files)
}

func ReadWorktreeFile(gitRepo *git.Repository, path string) ([]byte, error) {
	w, err := gitRepo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("unable to get git repository worktree: %w", err)
	}

	fs := w.Filesystem

	f, err := fs.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open git repository worktree file %q: %w", path, err)
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("unable to read git repository worktree file %q: %w", path, err)
	}

	return data, nil
}

func IsAncestor(gitRepo *git.Repository, ancestorCommit, descendantCommit string) (bool, error) {
	ancestorCommitObj, err := gitRepo.CommitObject(plumbing.NewHash(ancestorCommit))
	if err != nil {
		return false, fmt.Errorf("unable to get commit %q object: %w", ancestorCommit, err)
	}

	descendantCommitObj, err := gitRepo.CommitObject(plumbing.NewHash(descendantCommit))
	if err != nil {
		return false, fmt.Errorf("unable to get commit %q object: %w", descendantCommitObj, err)
	}

	isAncestor, err := ancestorCommitObj.IsAncestor(descendantCommitObj)
	if err != nil {
		return false, fmt.Errorf("unable to check ancestry of git commit %q to %q: %w", ancestorCommit, descendantCommit, err)
	}

	return isAncestor, nil
}
