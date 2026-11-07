package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"passpharse/internal/crypto"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "encrypt":
		runEncrypt(os.Args[2:])
	case "decrypt":
		runDecrypt(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  passpharse encrypt [-in FILE] [-out FILE] [-pass PASSWORD]
  passpharse decrypt [-in FILE] [-out FILE] [-pass PASSWORD]

Flags:
  -in   Input file. Omit or "-" to read from stdin (default).
  -out  Output file. Omit or "-" to write to stdout (default).
  -pass Password. Omit to prompt interactively (always reads from terminal).

Input/output modes:
  CLI to CLI   : passpharse encrypt            (stdin -> stdout)
  File to CLI  : passpharse encrypt -in f.txt  (file -> stdout)
  CLI to file  : passpharse encrypt -out f.b64 (stdin -> file)
  File to file : passpharse encrypt -in a -out b

Examples:
  echo "secret" | passpharse encrypt -pass "hunter2"
  echo "<base64>" | passpharse decrypt -pass "hunter2"
  passpharse encrypt -in plaintext.txt -out ciphertext.b64
  passpharse decrypt -in ciphertext.b64 -out plaintext.txt`)
}

func readPassword(prompt string) (string, error) {
	// Always read from the controlling terminal, never from stdin,
	// so piped input never interferes with the password prompt.
	tty, err := os.Open("/dev/tty")
	if err != nil {
		// No controlling terminal (non-interactive environment).
		// Only fall back to stdin if stdin is itself a terminal.
		if stat, e := os.Stdin.Stat(); e == nil && (stat.Mode()&os.ModeCharDevice) != 0 {
			return readLine(os.Stdin, prompt)
		}
		return "", fmt.Errorf("no terminal available for password prompt; use -pass flag")
	}
	defer tty.Close()
	return readLine(tty, prompt)
}

func readLine(r io.Reader, prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	reader := bufio.NewReader(r)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func readInput(path string) ([]byte, error) {
	if path == "" || path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func writeOutput(path string, data []byte) error {
	if path == "" || path == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func runEncrypt(args []string) {
	inPath, outPath, pass, interactive := parseFlags(args)

	// Read input first so piped stdin is consumed before any prompt.
	data, err := readInput(inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading input: %v\n", err)
		os.Exit(1)
	}

	if pass == "" {
		pass, err = readPassword("Password: ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading password: %v\n", err)
			os.Exit(1)
		}
		if pass == "" {
			fmt.Fprintln(os.Stderr, "password cannot be empty")
			os.Exit(1)
		}
		if interactive {
			conf, err := readPassword("Confirm password: ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "error reading confirmation: %v\n", err)
				os.Exit(1)
			}
			if conf != pass {
				fmt.Fprintln(os.Stderr, "passwords do not match")
				os.Exit(1)
			}
		}
	}

	encoded, err := crypto.Encrypt(data, []byte(pass))
	if err != nil {
		fmt.Fprintf(os.Stderr, "encryption error: %v\n", err)
		os.Exit(1)
	}

	out := encoded
	if outPath == "" || outPath == "-" {
		out += "\n" // trailing newline for terminal readability
	}

	if err := writeOutput(outPath, []byte(out)); err != nil {
		fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
		os.Exit(1)
	}
}

func runDecrypt(args []string) {
	inPath, outPath, pass, _ := parseFlags(args)

	data, err := readInput(inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading input: %v\n", err)
		os.Exit(1)
	}

	if pass == "" {
		pass, err = readPassword("Password: ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading password: %v\n", err)
			os.Exit(1)
		}
	}

	encoded := strings.TrimSpace(string(data))

	plaintext, err := crypto.Decrypt(encoded, []byte(pass))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if err := writeOutput(outPath, plaintext); err != nil {
		fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags(args []string) (inPath, outPath, pass string, interactive bool) {
	interactive = true
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-in":
			if i+1 < len(args) {
				inPath = args[i+1]
				i++
			}
		case "-out":
			if i+1 < len(args) {
				outPath = args[i+1]
				i++
			}
		case "-pass":
			if i+1 < len(args) {
				pass = args[i+1]
				interactive = false
				i++
			}
		}
	}
	return
}
