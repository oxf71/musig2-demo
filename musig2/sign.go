package musig2

import (
	"encoding/hex"
	"errors"
	"log"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

func decodeHex(hexStr string) []byte {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		panic("invalid hex string in test source: err " + err.Error() +
			", hex: " + hexStr)
	}

	return b
}

func TwoPrivSign2(privKey1, privKey2 *btcec.PrivateKey, msg [32]byte) (*schnorr.Signature, []byte, error) {

	// If we try to make a context, with just the private key and sorting
	// value, we should get an error.
	_, err := musig2.NewContext(privKey1, true)
	if !errors.Is(err, musig2.ErrSignersNotSpecified) {
		log.Fatalf("unexpected ctx error: %v", err)
	}

	signers := []*btcec.PublicKey{privKey1.PubKey(), privKey2.PubKey()}
	numSigners := len(signers)

	ctx1, err := musig2.NewContext(
		privKey1, true, musig2.WithNumSigners(numSigners), musig2.WithEarlyNonceGen(),
	)
	if err != nil {
		log.Fatalf("unable to make ctx: %v", err)
	}
	pubKey1 := ctx1.PubKey()

	ctx2, err := musig2.NewContext(
		privKey2, true, musig2.WithKnownSigners(signers), musig2.WithEarlyNonceGen(),
	)
	if err != nil {
		log.Fatalf("unable to make ctx: %v", err)
	}
	pubKey2 := ctx2.PubKey()

	// At this point, the combined key shouldn't be available for signer 1,
	// but should be for signer 2, as they know about all signers.
	if _, err := ctx1.CombinedKey(); !errors.Is(err, musig2.ErrNotEnoughSigners) {
		log.Fatalf("unepxected error: %v", err)
	}
	_, err = ctx2.CombinedKey()
	if err != nil {
		log.Fatalf("unable to get combined key: %v", err)
	}

	// The early nonces _should_ be available at this point.
	nonce1, err := ctx1.EarlySessionNonce()
	if err != nil {
		log.Fatalf("session nonce not available: %v", err)
	}
	nonce2, err := ctx2.EarlySessionNonce()
	if err != nil {
		log.Fatalf("session nonce not available: %v", err)
	}

	// The number of registered signers should still be 1 for both parties.
	if ctx1.NumRegisteredSigners() != 1 {
		log.Fatalf("expected 1 signer, instead have: %v",
			ctx1.NumRegisteredSigners())
	}
	if ctx2.NumRegisteredSigners() != 2 {
		log.Fatalf("expected 2 signers, instead have: %v",
			ctx2.NumRegisteredSigners())
	}

	// If we try to make a session, we should get an error since we dn't
	// have all the signers yet.
	if _, err := ctx1.NewSession(); !errors.Is(err, musig2.ErrNotEnoughSigners) {
		log.Fatalf("unexpected session key error: %v", err)
	}

	// The combined key should also be unavailable as well.
	if _, err := ctx1.CombinedKey(); !errors.Is(err, musig2.ErrNotEnoughSigners) {
		log.Fatalf("unexpected combined key error: %v", err)
	}

	// We'll now register the other signer for party 1.
	done, err := ctx1.RegisterSigner(&pubKey2)
	if err != nil {
		log.Fatalf("unable to register signer: %v", err)
	}
	if !done {
		log.Fatalf("signer 1 doesn't have all keys")
	}

	// If we try to register the signer again, we should get an error.
	_, err = ctx2.RegisterSigner(&pubKey1)
	if !errors.Is(err, musig2.ErrAlreadyHaveAllSigners) {
		log.Fatalf("should not be able to register too many signers")
	}

	// We should be able to create the session at this point.
	session1, err := ctx1.NewSession()
	if err != nil {
		log.Fatalf("unable to create new session: %v", err)
	}
	session2, err := ctx2.NewSession()
	if err != nil {
		log.Fatalf("unable to create new session: %v", err)
	}

	// If we try to sign before we have the combined nonce, we shoudl get
	// an error.
	_, err = session1.Sign(msg)
	if !errors.Is(err, musig2.ErrCombinedNonceUnavailable) {
		log.Fatalf("unable to gen sig: %v", err)
	}

	// Now we can exchange nonces to continue with the rest of the signing
	// process as normal.
	done, err = session1.RegisterPubNonce(nonce2.PubNonce)
	if err != nil {
		log.Fatalf("unable to register nonce: %v", err)
	}
	if !done {
		log.Fatalf("signer 1 doesn't have all nonces")
	}
	done, err = session2.RegisterPubNonce(nonce1.PubNonce)
	if err != nil {
		log.Fatalf("unable to register nonce: %v", err)
	}
	if !done {
		log.Fatalf("signer 2 doesn't have all nonces")
	}

	// Registering the nonce again should error out.
	_, err = session2.RegisterPubNonce(nonce1.PubNonce)
	if !errors.Is(err, musig2.ErrAlredyHaveAllNonces) {
		log.Fatalf("shouldn't be able to register nonces twice")
	}

	// Sign the message and combine the two partial sigs into one.
	_, err = session1.Sign(msg)
	if err != nil {
		log.Fatalf("unable to gen sig: %v", err)
	}
	sig2, err := session2.Sign(msg)
	if err != nil {
		log.Fatalf("unable to gen sig: %v", err)
	}
	done, err = session1.CombineSig(sig2)
	if err != nil {
		log.Fatalf("unable to combine sig: %v", err)
	}
	if !done {
		log.Fatalf("all sigs should be known now: %v", err)
	}

	// If we try to combine another sig, then we should get an error.
	_, err = session1.CombineSig(sig2)
	if !errors.Is(err, musig2.ErrAlredyHaveAllSigs) {
		log.Fatalf("shouldn't be able to combine again")
	}

	finalSig := session1.FinalSig()

	return finalSig, msg[:], nil
}

func TwoPrivSign(priv1, priv2 string, msg [32]byte) (*schnorr.Signature, []byte, error) {
	privKey1, _ := btcec.PrivKeyFromBytes(decodeHex(priv1))
	privKey2, _ := btcec.PrivKeyFromBytes(decodeHex(priv2))

	// If we try to make a context, with just the private key and sorting
	// value, we should get an error.
	_, err := musig2.NewContext(privKey1, true)
	if !errors.Is(err, musig2.ErrSignersNotSpecified) {
		log.Fatalf("unexpected ctx error: %v", err)
	}

	signers := []*btcec.PublicKey{privKey1.PubKey(), privKey2.PubKey()}
	numSigners := len(signers)

	ctx1, err := musig2.NewContext(
		privKey1, true, musig2.WithNumSigners(numSigners), musig2.WithEarlyNonceGen(),
	)
	if err != nil {
		log.Fatalf("unable to make ctx: %v", err)
	}
	pubKey1 := ctx1.PubKey()

	ctx2, err := musig2.NewContext(
		privKey2, true, musig2.WithKnownSigners(signers), musig2.WithEarlyNonceGen(),
	)
	if err != nil {
		log.Fatalf("unable to make ctx: %v", err)
	}
	pubKey2 := ctx2.PubKey()

	// At this point, the combined key shouldn't be available for signer 1,
	// but should be for signer 2, as they know about all signers.
	if _, err := ctx1.CombinedKey(); !errors.Is(err, musig2.ErrNotEnoughSigners) {
		log.Fatalf("unepxected error: %v", err)
	}
	_, err = ctx2.CombinedKey()
	if err != nil {
		log.Fatalf("unable to get combined key: %v", err)
	}

	// The early nonces _should_ be available at this point.
	nonce1, err := ctx1.EarlySessionNonce()
	if err != nil {
		log.Fatalf("session nonce not available: %v", err)
	}
	nonce2, err := ctx2.EarlySessionNonce()
	if err != nil {
		log.Fatalf("session nonce not available: %v", err)
	}

	// The number of registered signers should still be 1 for both parties.
	if ctx1.NumRegisteredSigners() != 1 {
		log.Fatalf("expected 1 signer, instead have: %v",
			ctx1.NumRegisteredSigners())
	}
	if ctx2.NumRegisteredSigners() != 2 {
		log.Fatalf("expected 2 signers, instead have: %v",
			ctx2.NumRegisteredSigners())
	}

	// If we try to make a session, we should get an error since we dn't
	// have all the signers yet.
	if _, err := ctx1.NewSession(); !errors.Is(err, musig2.ErrNotEnoughSigners) {
		log.Fatalf("unexpected session key error: %v", err)
	}

	// The combined key should also be unavailable as well.
	if _, err := ctx1.CombinedKey(); !errors.Is(err, musig2.ErrNotEnoughSigners) {
		log.Fatalf("unexpected combined key error: %v", err)
	}

	// We'll now register the other signer for party 1.
	done, err := ctx1.RegisterSigner(&pubKey2)
	if err != nil {
		log.Fatalf("unable to register signer: %v", err)
	}
	if !done {
		log.Fatalf("signer 1 doesn't have all keys")
	}

	// If we try to register the signer again, we should get an error.
	_, err = ctx2.RegisterSigner(&pubKey1)
	if !errors.Is(err, musig2.ErrAlreadyHaveAllSigners) {
		log.Fatalf("should not be able to register too many signers")
	}

	// We should be able to create the session at this point.
	session1, err := ctx1.NewSession()
	if err != nil {
		log.Fatalf("unable to create new session: %v", err)
	}
	session2, err := ctx2.NewSession()
	if err != nil {
		log.Fatalf("unable to create new session: %v", err)
	}

	// If we try to sign before we have the combined nonce, we shoudl get
	// an error.
	_, err = session1.Sign(msg)
	if !errors.Is(err, musig2.ErrCombinedNonceUnavailable) {
		log.Fatalf("unable to gen sig: %v", err)
	}

	// Now we can exchange nonces to continue with the rest of the signing
	// process as normal.
	done, err = session1.RegisterPubNonce(nonce2.PubNonce)
	if err != nil {
		log.Fatalf("unable to register nonce: %v", err)
	}
	if !done {
		log.Fatalf("signer 1 doesn't have all nonces")
	}
	done, err = session2.RegisterPubNonce(nonce1.PubNonce)
	if err != nil {
		log.Fatalf("unable to register nonce: %v", err)
	}
	if !done {
		log.Fatalf("signer 2 doesn't have all nonces")
	}

	// Registering the nonce again should error out.
	_, err = session2.RegisterPubNonce(nonce1.PubNonce)
	if !errors.Is(err, musig2.ErrAlredyHaveAllNonces) {
		log.Fatalf("shouldn't be able to register nonces twice")
	}

	// Sign the message and combine the two partial sigs into one.
	_, err = session1.Sign(msg)
	if err != nil {
		log.Fatalf("unable to gen sig: %v", err)
	}
	sig2, err := session2.Sign(msg)
	if err != nil {
		log.Fatalf("unable to gen sig: %v", err)
	}
	done, err = session1.CombineSig(sig2)
	if err != nil {
		log.Fatalf("unable to combine sig: %v", err)
	}
	if !done {
		log.Fatalf("all sigs should be known now: %v", err)
	}

	// If we try to combine another sig, then we should get an error.
	_, err = session1.CombineSig(sig2)
	if !errors.Is(err, musig2.ErrAlredyHaveAllSigs) {
		log.Fatalf("shouldn't be able to combine again")
	}

	finalSig := session1.FinalSig()

	return finalSig, msg[:], nil
}

func TwoBtcAddress(priv1, priv2 *btcec.PrivateKey) string {
	// Finally, verify that the final signature is valid.
	combinedKey, err := address(priv1, priv2)
	if err != nil {
		log.Fatalf("unexpected combined key error: %v", err)
	}
	combinedAddress, err := btcutil.NewAddressPubKey(combinedKey.SerializeCompressed(), &chaincfg.TestNet3Params)
	if err != nil {
		log.Fatalf("unable to gen pub key: %v", err)
	}
	return combinedAddress.EncodeAddress()
}

func TwoBtcTaprootAddress(priv1, priv2 *btcec.PrivateKey) string {
	// Finally, verify that the final signature is valid.
	combinedKey, err := address(priv1, priv2)
	if err != nil {
		log.Fatalf("unexpected combined key error: %v", err)
	}
	utxoTaprootAddress, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(combinedKey)), &chaincfg.TestNet3Params)
	if err != nil {
		log.Fatal(err)
	}
	return utxoTaprootAddress.EncodeAddress()
}

func address(privKey1, privKey2 *btcec.PrivateKey) (*btcec.PublicKey, error) {
	// privKey1, _ := btcec.PrivKeyFromBytes(decodeHex(priv1))
	// privKey2, _ := btcec.PrivKeyFromBytes(decodeHex(priv2))

	// If we try to make a context, with just the private key and sorting
	// value, we should get an error.
	_, err := musig2.NewContext(privKey1, true)
	if !errors.Is(err, musig2.ErrSignersNotSpecified) {
		log.Fatalf("unexpected ctx error: %v", err)
	}

	signers := []*btcec.PublicKey{privKey1.PubKey(), privKey2.PubKey()}
	numSigners := len(signers)

	ctx1, err := musig2.NewContext(
		privKey1, true, musig2.WithNumSigners(numSigners), musig2.WithEarlyNonceGen(),
	)
	if err != nil {
		log.Fatalf("unable to make ctx: %v", err)
	}
	pubKey1 := ctx1.PubKey()

	ctx2, err := musig2.NewContext(
		privKey2, true, musig2.WithKnownSigners(signers), musig2.WithEarlyNonceGen(),
	)
	if err != nil {
		log.Fatalf("unable to make ctx: %v", err)
	}
	pubKey2 := ctx2.PubKey()

	// At this point, the combined key shouldn't be available for signer 1,
	// but should be for signer 2, as they know about all signers.
	if _, err := ctx1.CombinedKey(); !errors.Is(err, musig2.ErrNotEnoughSigners) {
		log.Fatalf("unepxected error: %v", err)
	}
	_, err = ctx2.CombinedKey()
	if err != nil {
		log.Fatalf("unable to get combined key: %v", err)
	}

	// The number of registered signers should still be 1 for both parties.
	if ctx1.NumRegisteredSigners() != 1 {
		log.Fatalf("expected 1 signer, instead have: %v",
			ctx1.NumRegisteredSigners())
	}
	if ctx2.NumRegisteredSigners() != 2 {
		log.Fatalf("expected 2 signers, instead have: %v",
			ctx2.NumRegisteredSigners())
	}

	// If we try to make a session, we should get an error since we dn't
	// have all the signers yet.
	if _, err := ctx1.NewSession(); !errors.Is(err, musig2.ErrNotEnoughSigners) {
		log.Fatalf("unexpected session key error: %v", err)
	}

	// The combined key should also be unavailable as well.
	if _, err := ctx1.CombinedKey(); !errors.Is(err, musig2.ErrNotEnoughSigners) {
		log.Fatalf("unexpected combined key error: %v", err)
	}

	// We'll now register the other signer for party 1.
	done, err := ctx1.RegisterSigner(&pubKey2)
	if err != nil {
		log.Fatalf("unable to register signer: %v", err)
	}
	if !done {
		log.Fatalf("signer 1 doesn't have all keys")
	}

	// If we try to register the signer again, we should get an error.
	_, err = ctx2.RegisterSigner(&pubKey1)
	if !errors.Is(err, musig2.ErrAlreadyHaveAllSigners) {
		log.Fatalf("should not be able to register too many signers")
	}

	// Finally, verify that the final signature is valid.
	combinedKey, err := ctx1.CombinedKey()
	if err != nil {
		log.Fatalf("unexpected combined key error: %v", err)
	}
	return combinedKey, nil
}

func TwoCombinedKey(priv1, priv2 *btcec.PrivateKey) (*btcec.PublicKey, error) {
	return address(priv1, priv2)
}
