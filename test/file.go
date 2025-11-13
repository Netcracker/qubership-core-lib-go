package test

import (
	"os"
	"path/filepath"
)

func LoadFileContent(filePath string) []byte {
	absPath, _ := filepath.Abs(filePath)
	content, _ := os.ReadFile(absPath)
	return content
}
