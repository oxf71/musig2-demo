package musig2

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
)

// TestMuSigEarlyNonce tests that for protocols where nonces need to be
// exchagned before all signers are known, the context API works as expected.
func TestMuSigEarlyNonce(t *testing.T) {
	t.Parallel()

	privKey1, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("unable to gen priv key: %v", err)
	}
	privKey2, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("unable to gen priv key: %v", err)
	}

	// If we try to make a context, with just the private key and sorting
	// value, we should get an error.
	_, err = musig2.NewContext(privKey1, true)
	if !errors.Is(err, musig2.ErrSignersNotSpecified) {
		t.Fatalf("unexpected ctx error: %v", err)
	}

	signers := []*btcec.PublicKey{privKey1.PubKey(), privKey2.PubKey()}
	numSigners := len(signers)

	ctx1, err := musig2.NewContext(
		privKey1, true, musig2.WithNumSigners(numSigners), musig2.WithEarlyNonceGen(),
	)
	if err != nil {
		t.Fatalf("unable to make ctx: %v", err)
	}
	pubKey1 := ctx1.PubKey()

	ctx2, err := musig2.NewContext(
		privKey2, true, musig2.WithKnownSigners(signers), musig2.WithEarlyNonceGen(),
	)
	if err != nil {
		t.Fatalf("unable to make ctx: %v", err)
	}
	pubKey2 := ctx2.PubKey()

	// At this point, the combined key shouldn't be available for signer 1,
	// but should be for signer 2, as they know about all signers.
	if _, err := ctx1.CombinedKey(); !errors.Is(err, musig2.ErrNotEnoughSigners) {
		t.Fatalf("unepxected error: %v", err)
	}
	_, err = ctx2.CombinedKey()
	if err != nil {
		t.Fatalf("unable to get combined key: %v", err)
	}

	// The early nonces _should_ be available at this point.
	nonce1, err := ctx1.EarlySessionNonce()
	if err != nil {
		t.Fatalf("session nonce not available: %v", err)
	}
	nonce2, err := ctx2.EarlySessionNonce()
	if err != nil {
		t.Fatalf("session nonce not available: %v", err)
	}

	// The number of registered signers should still be 1 for both parties.
	if ctx1.NumRegisteredSigners() != 1 {
		t.Fatalf("expected 1 signer, instead have: %v",
			ctx1.NumRegisteredSigners())
	}
	if ctx2.NumRegisteredSigners() != 2 {
		t.Fatalf("expected 2 signers, instead have: %v",
			ctx2.NumRegisteredSigners())
	}

	// If we try to make a session, we should get an error since we dn't
	// have all the signers yet.
	if _, err := ctx1.NewSession(); !errors.Is(err, musig2.ErrNotEnoughSigners) {
		t.Fatalf("unexpected session key error: %v", err)
	}

	// The combined key should also be unavailable as well.
	if _, err := ctx1.CombinedKey(); !errors.Is(err, musig2.ErrNotEnoughSigners) {
		t.Fatalf("unexpected combined key error: %v", err)
	}

	// We'll now register the other signer for party 1.
	done, err := ctx1.RegisterSigner(&pubKey2)
	if err != nil {
		t.Fatalf("unable to register signer: %v", err)
	}
	if !done {
		t.Fatalf("signer 1 doesn't have all keys")
	}

	// If we try to register the signer again, we should get an error.
	_, err = ctx2.RegisterSigner(&pubKey1)
	if !errors.Is(err, musig2.ErrAlreadyHaveAllSigners) {
		t.Fatalf("should not be able to register too many signers")
	}

	// We should be able to create the session at this point.
	session1, err := ctx1.NewSession()
	if err != nil {
		t.Fatalf("unable to create new session: %v", err)
	}
	session2, err := ctx2.NewSession()
	if err != nil {
		t.Fatalf("unable to create new session: %v", err)
	}

	msg := sha256.Sum256([]byte("let's get taprooty, LN style"))

	// If we try to sign before we have the combined nonce, we shoudl get
	// an error.
	_, err = session1.Sign(msg)
	if !errors.Is(err, musig2.ErrCombinedNonceUnavailable) {
		t.Fatalf("unable to gen sig: %v", err)
	}

	// Now we can exchange nonces to continue with the rest of the signing
	// process as normal.
	done, err = session1.RegisterPubNonce(nonce2.PubNonce)
	if err != nil {
		t.Fatalf("unable to register nonce: %v", err)
	}
	if !done {
		t.Fatalf("signer 1 doesn't have all nonces")
	}
	done, err = session2.RegisterPubNonce(nonce1.PubNonce)
	if err != nil {
		t.Fatalf("unable to register nonce: %v", err)
	}
	if !done {
		t.Fatalf("signer 2 doesn't have all nonces")
	}

	// Registering the nonce again should error out.
	_, err = session2.RegisterPubNonce(nonce1.PubNonce)
	if !errors.Is(err, musig2.ErrAlredyHaveAllNonces) {
		t.Fatalf("shouldn't be able to register nonces twice")
	}

	// Sign the message and combine the two partial sigs into one.
	_, err = session1.Sign(msg)
	if err != nil {
		t.Fatalf("unable to gen sig: %v", err)
	}
	sig2, err := session2.Sign(msg)
	if err != nil {
		t.Fatalf("unable to gen sig: %v", err)
	}
	done, err = session1.CombineSig(sig2)
	if err != nil {
		t.Fatalf("unable to combine sig: %v", err)
	}
	if !done {
		t.Fatalf("all sigs should be known now: %v", err)
	}

	// If we try to combine another sig, then we should get an error.
	_, err = session1.CombineSig(sig2)
	if !errors.Is(err, musig2.ErrAlredyHaveAllSigs) {
		t.Fatalf("shouldn't be able to combine again")
	}

	// Finally, verify that the final signature is valid.
	combinedKey, err := ctx1.CombinedKey()
	if err != nil {
		t.Fatalf("unexpected combined key error: %v", err)
	}
	finalSig := session1.FinalSig()
	if !finalSig.Verify(msg[:], combinedKey) {
		t.Fatalf("final sig is invalid!")
	}
}
