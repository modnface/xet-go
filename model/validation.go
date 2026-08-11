package model

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	MaxNamespaceRunes = 96
	MaxRepoNameRunes  = 96
	MaxPathBytes      = 4096
	MaxPathComponent  = 255
	MaxRefBytes       = 1024
	MaxIdentityBytes  = 255
	MaxMessageBytes   = 16 << 10
)

func validateRepoComponent(label, value string, maxRunes int) error {
	if !utf8.ValidString(value) || !norm.NFC.IsNormalString(value) {
		return fmt.Errorf("model: %s must be valid NFC UTF-8", label)
	}
	count := utf8.RuneCountInString(value)
	if count < 1 || count > maxRunes {
		return fmt.Errorf("model: %s length must be inside [1,%d] Unicode code points", label, maxRunes)
	}
	if value[0] == '-' || value[0] == '.' || value[len(value)-1] == '-' || value[len(value)-1] == '.' {
		return fmt.Errorf("model: %s cannot begin or end with '-' or '.'", label)
	}
	if strings.Contains(value, "--") || strings.Contains(value, "..") || strings.HasSuffix(value, ".git") {
		return fmt.Errorf("model: %s contains a reserved sequence", label)
	}
	for _, character := range value {
		if character == '_' || character == '-' || character == '.' ||
			unicode.IsLetter(character) || unicode.IsDigit(character) {
			continue
		}
		return fmt.Errorf("model: %s contains unsupported character %q", label, character)
	}
	return nil
}

func ParseFilePath(value string) (FilePath, error) {
	if !utf8.ValidString(value) || !norm.NFC.IsNormalString(value) {
		return "", fmt.Errorf("model: file path must be valid NFC UTF-8")
	}
	if len(value) < 1 || len(value) > MaxPathBytes || strings.HasPrefix(value, "/") ||
		strings.HasSuffix(value, "/") || strings.Contains(value, "\\") {
		return "", fmt.Errorf("model: file path is empty, oversized, absolute, or noncanonical")
	}
	for _, character := range value {
		if unsafeUnicode(character) {
			return "", fmt.Errorf("model: file path contains an unsafe character")
		}
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." ||
			component == ".git" || component == ".cache" || len(component) > MaxPathComponent {
			return "", fmt.Errorf("model: file path contains an empty, reserved, or oversized component")
		}
	}
	return FilePath(value), nil
}

// ParseFilePrefix validates a lexical path prefix used for bounded tree
// queries. The empty prefix selects the complete tree; one trailing slash is
// allowed to select descendants of a directory.
func ParseFilePrefix(value string) (FilePrefix, error) {
	if value == "" {
		return "", nil
	}
	path := strings.TrimSuffix(value, "/")
	if path == "" || strings.HasSuffix(path, "/") {
		return "", fmt.Errorf("model: file prefix is noncanonical")
	}
	if _, err := ParseFilePath(path); err != nil {
		return "", fmt.Errorf("model: file prefix: %w", err)
	}
	return FilePrefix(value), nil
}

func ParseRefName(value string) (RefName, error) {
	if !utf8.ValidString(value) || !norm.NFC.IsNormalString(value) {
		return "", fmt.Errorf("model: ref must be valid NFC UTF-8")
	}
	if len(value) < 1 || len(value) > MaxRefBytes || value == "@" ||
		strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") ||
		strings.HasSuffix(value, ".") || strings.Contains(value, "//") ||
		strings.Contains(value, "..") || strings.Contains(value, "@{") {
		return "", fmt.Errorf("model: ref is empty, oversized, ambiguous, or noncanonical")
	}
	if len(value) == 40 {
		if looksLikeOID(value) {
			return "", fmt.Errorf("model: ref cannot be indistinguishable from a commit OID")
		}
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." ||
			strings.HasPrefix(component, ".") || strings.HasSuffix(component, ".lock") {
			return "", fmt.Errorf("model: ref contains a reserved component")
		}
	}
	for _, character := range value {
		if unsafeUnicode(character) || unicode.IsSpace(character) || strings.ContainsRune("~^:?*[\\", character) {
			return "", fmt.Errorf("model: ref contains an unsafe character")
		}
	}
	return RefName(value), nil
}

func looksLikeOID(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func validateText(label, value string, maximum int, required, allowFormatting bool) error {
	if !utf8.ValidString(value) || !norm.NFC.IsNormalString(value) {
		return fmt.Errorf("model: %s must be valid NFC UTF-8", label)
	}
	if required && value == "" {
		return fmt.Errorf("model: %s is required", label)
	}
	if len(value) > maximum {
		return fmt.Errorf("model: %s exceeds %d bytes", label, maximum)
	}
	for _, character := range value {
		if allowFormatting && (character == '\n' || character == '\t') {
			continue
		}
		if unsafeUnicode(character) {
			return fmt.Errorf("model: %s contains an unsafe character", label)
		}
	}
	return nil
}

func unsafeUnicode(character rune) bool {
	return character == utf8.RuneError || character == 0 || unicode.IsControl(character) ||
		unicode.Is(unicode.Cf, character)
}
