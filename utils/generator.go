package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
)

// IDGenerator manages the generation of unique 8-character alphanumeric IDs
type IDGenerator struct {
	// Track recently generated IDs to ensure uniqueness
	usedIDs      map[string]bool
	mutex        sync.Mutex
	characterSet []rune
}

// NewIDGenerator creates a new instance of IDGenerator
func NewIDGenerator() *IDGenerator {
	// Use only capital letters and numbers for better legibility
	// Omitting easily confused characters: 0, O, 1, I
	characterSet := []rune("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")

	return &IDGenerator{
		usedIDs:      make(map[string]bool),
		characterSet: characterSet,
	}
}

// GenerateID creates a new unique 8-character ID
func (g *IDGenerator) GenerateID() (string, error) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	// Seed with current time to add entropy

	// Maximum attempts to avoid infinite loops
	maxAttempts := 100
	attempts := 0

	for attempts < maxAttempts {
		attempts++

		// Generate ID
		id, err := g.generateRandomID(8)
		if err != nil {
			return "", err
		}

		// Check if ID is already used
		if !g.usedIDs[id] {
			g.usedIDs[id] = true
			return id, nil
		}
	}

	return "", fmt.Errorf("failed to generate unique ID after %d attempts", maxAttempts)
}

// generateRandomID creates a random ID of specified length
func (g *IDGenerator) generateRandomID(length int) (string, error) {
	result := make([]rune, length)

	// Get character set length
	charSetLength := big.NewInt(int64(len(g.characterSet)))

	for i := 0; i < length; i++ {
		// Generate cryptographically secure random number
		randomIndex, err := rand.Int(rand.Reader, charSetLength)
		if err != nil {
			return "", err
		}

		// Select character from set
		result[i] = g.characterSet[randomIndex.Int64()]
	}

	return string(result), nil
}

// CleanupOldIDs removes old IDs to prevent memory leaks when using long-term
// Only use this if your application runs for extended periods
func (g *IDGenerator) CleanupOldIDs(maxSize int) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	// If the used IDs map gets too large, reset it
	// In a production system, you'd want to store IDs in a database
	if len(g.usedIDs) > maxSize {
		g.usedIDs = make(map[string]bool)
	}
}
