package crawler

import (
	"bufio"
	"context"
	"os"
	"strings"
)

type WordlistLoader interface {
	Load(ctx context.Context) ([]string, error)
}

type FileWordlist struct {
	Path string
}

func NewFileWordlist(path string) *FileWordlist {
	return &FileWordlist{Path: path}
}

func (w *FileWordlist) Load(ctx context.Context) ([]string, error) {
	file, err := os.Open(w.Path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var paths []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return paths, ctx.Err()
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		paths = append(paths, line)
	}

	return paths, scanner.Err()
}

type BuiltinWordlist struct{}

func NewBuiltinWordlist() *BuiltinWordlist {
	return &BuiltinWordlist{}
}

var builtinPaths = []string{
	"admin", "login", "wp-admin", "administrator",
	"backup", "backups", "db_backup", "database",
	".git", ".git/config", ".git/HEAD",
	".env", ".env.local", ".env.production",
	"config", "configuration", "config.php", "config.json",
	"api", "api/v1", "api/v2", "api/swagger", "api/docs",
	"robots.txt", "sitemap.xml", "sitemap",
	"index", "index.php", "index.html", "index.htm",
	"test", "tests", "testing",
	"dev", "development", "staging",
	"private", "secret", "secrets",
	"debug", "logs", "error.log", "access.log",
	"phpinfo.php", "info.php", "status",
	".htaccess", ".htpasswd",
	"crossdomain.xml", "clientaccesspolicy.xml",
	"server-status", "server-info",
	"version", "VERSION", "CHANGELOG",
	"Dockerfile", "docker-compose.yml",
	"package.json", "composer.json",
	"web.config", "application.properties",
}

func (w *BuiltinWordlist) Load(ctx context.Context) ([]string, error) {
	return builtinPaths, nil
}
