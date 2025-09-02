package tokensource

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFileTokenSource(t *testing.T) {
	tokenDir := t.TempDir()
	tokenFilePath := tokenDir + "/token"
	dataSymlinkPath := tokenDir + "/..data"
	tokenFile, err := os.CreateTemp(tokenDir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer tokenFile.Close()
	err = os.Symlink(tokenFile.Name(), dataSymlinkPath)
	if err != nil {
		t.Fatal(err)
	}
	err = os.Symlink(dataSymlinkPath, tokenFilePath)
	if err != nil {
		t.Fatal(err)
	}

	firstValidToken := "first_valid_token"
	_, err = tokenFile.Write([]byte(firstValidToken))
	if err != nil {
		t.Fatal(err)
	}

	fts, err := New(context.Background(), tokenDir)
	if err != nil {
		t.Fatal(err)
	}
	token, err := fts.Token()
	if err != nil {
		t.Fatal(err)
	}
	if firstValidToken != token {
		t.Errorf("expected token %s, got %s", firstValidToken, token)
	}

	secondValidToken := "second_valid_token"
	_, err = tokenFile.WriteAt([]byte(secondValidToken), 0)
	if err != nil {
		t.Fatal(err)
	}
	err = os.Remove(dataSymlinkPath)
	if err != nil {
		t.Fatal(err)
	}
	err = os.Symlink(tokenFile.Name(), dataSymlinkPath)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Millisecond * 50)
	token, err = fts.Token()
	if err != nil {
		t.Fatal(err)
	}
	if secondValidToken != token {
		t.Errorf("expected token %s, got %s", secondValidToken, token)
	}
}

func TestFileTokenSourceRace(t *testing.T) {
	tokenDir := t.TempDir()
	tokenFilePath := tokenDir + "/token"
	dataSymlinkPath := tokenDir + "/..data"
	tokenFile, err := os.CreateTemp(tokenDir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer tokenFile.Close()
	err = os.Symlink(tokenFile.Name(), dataSymlinkPath)
	if err != nil {
		t.Fatal(err)
	}
	err = os.Symlink(dataSymlinkPath, tokenFilePath)
	if err != nil {
		t.Fatal(err)
	}

	var newCalledCount atomic.Int32
	newFileTokenSource = func(ctx context.Context, tokenDir string) (*fileTokenSource, error) {
		newCalledCount.Add(1)
		return &fileTokenSource{}, nil
	}

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			_, err = New(context.Background(), tokenDir)
			if err != nil {
				panic(err)
			}
			wg.Done()
		}()
	}
	wg.Wait()

	if count := newCalledCount.Load(); count > 1 {
		t.Fatalf("expected newFileTokenSource to be called only 1 time, got %d", count)
	}
}
