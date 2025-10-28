package test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func LoadFileContent(t *testing.T, filePath string) []byte {
	absPath, err := filepath.Abs(filePath)
	assert.Nil(t, err)
	content, err := os.ReadFile(absPath)
	assert.Nil(t, err)
	return content
}
