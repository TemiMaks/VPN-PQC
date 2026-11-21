package cipher

// ReplayWindow is the 64-bit sliding window anti-replay state.
type ReplayWindow struct {
	// TODO: Add the highest authenticated counter and the sliding window bitmap.
}

// Check reports whether counter is acceptable without mutating replay state.
func (w *ReplayWindow) Check(counter uint64) error {
	// TODO: Implement 64-bit sliding window anti-replay checking.
	return nil
}

// Update records an authenticated counter after AEAD authentication succeeds.
func (w *ReplayWindow) Update(counter uint64) {
	// TODO: Update the highest counter and 64-bit sliding window bitmap.
}
