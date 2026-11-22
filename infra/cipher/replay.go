package cipher

import "pqc-vpn/domain"

const ReplayWindowSize = 64

// ReplayWindow is the 64-bit sliding window anti-replay state.
type ReplayWindow struct {
	initialized bool
	maxCounter  uint64
	bitmap      uint64
}

// Check reports whether counter is acceptable without mutating replay state.
func (w *ReplayWindow) Check(counter uint64) error {
	if !w.initialized || counter > w.maxCounter {
		return nil
	}

	diff := w.maxCounter - counter
	if diff >= ReplayWindowSize || (w.bitmap&(uint64(1)<<diff)) != 0 {
		return domain.ErrReplayAttack
	}

	return nil
}

// Update records an authenticated counter after AEAD authentication succeeds.
func (w *ReplayWindow) Update(counter uint64) {
	if !w.initialized {
		w.initialized = true
		w.maxCounter = counter
		w.bitmap = 1
		return
	}

	if counter > w.maxCounter {
		shift := counter - w.maxCounter
		if shift >= 64 {
			w.bitmap = 1
		} else {
			w.bitmap = (w.bitmap << shift) | 1
		}
		w.maxCounter = counter
		return
	}

	diff := w.maxCounter - counter
	if diff < ReplayWindowSize {
		w.bitmap |= uint64(1) << diff
	}
}
