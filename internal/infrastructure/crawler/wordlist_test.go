package crawler

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuiltinWordlist(t *testing.T) {
	w := NewBuiltinWordlist()
	paths, err := w.Load(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, paths)
	assert.Contains(t, paths, "admin")
	assert.Contains(t, paths, ".git/config")
	assert.Contains(t, paths, ".env")
	assert.Contains(t, paths, "robots.txt")
}

func TestFileWordlist_Load(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "words.txt")
	content := "admin\n# this is a comment\nbackup\n\n.git\n"
	err := os.WriteFile(filePath, []byte(content), 0644)
	require.NoError(t, err)

	w := NewFileWordlist(filePath)
	paths, err := w.Load(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"admin", "backup", ".git"}, paths)
}

func TestFileWordlist_NotFound(t *testing.T) {
	w := NewFileWordlist("/nonexistent/path.txt")
	_, err := w.Load(context.Background())
	assert.Error(t, err)
}

func TestFileWordlist_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "empty.txt")
	err := os.WriteFile(filePath, []byte(""), 0644)
	require.NoError(t, err)

	w := NewFileWordlist(filePath)
	paths, err := w.Load(context.Background())
	require.NoError(t, err)
	assert.Empty(t, paths)
}

func TestFileWordlist_ContextCancellation(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "large.txt")
	content := "admin\nbackup\nsecret\n"
	err := os.WriteFile(filePath, []byte(content), 0644)
	require.NoError(t, err)

	w := NewFileWordlist(filePath)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = w.Load(ctx)
	assert.Error(t, err)
}
