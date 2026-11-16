package secretbox

import "testing"

func TestEncryptDecryptRoundTrip(t *testing.T) {
	box, err := New(Derive("test-passphrase"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	plaintext := []byte(`{"token":"super-secret"}`)
	ct, err := box.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if ct == string(plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}
	got, err := box.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestEncryptUsesFreshNonce(t *testing.T) {
	box, _ := New(Derive("k"))
	first, _ := box.Encrypt([]byte("same"))
	second, _ := box.Encrypt([]byte("same"))
	if first == second {
		t.Error("two encryptions of the same plaintext must differ (random nonce)")
	}
}

func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	box, _ := New(Derive("k"))
	ct, _ := box.Encrypt([]byte("data"))
	tampered := []byte(ct)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := box.Decrypt(string(tampered)); err == nil {
		t.Error("tampered ciphertext must not decrypt")
	}
}

func TestNewRejectsWrongKeySize(t *testing.T) {
	if _, err := New([]byte("too-short")); err == nil {
		t.Error("expected error for short key")
	}
}
