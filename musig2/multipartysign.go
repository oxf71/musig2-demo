package musig2

import (
	"log"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
)

func MultiPartySign(signerKeys []*btcec.PrivateKey, taprootTweak []byte, msg [32]byte,
	tweaks ...musig2.KeyTweakDesc) (*schnorr.Signature, *btcec.PublicKey, []byte, error) {

	numSigners := len(signerKeys)

	// First generate the set of signers along with their public keys.
	// signerKeys := make([]*btcec.PrivateKey, numSigners)
	signSet := make([]*btcec.PublicKey, numSigners)
	for i := 0; i < numSigners; i++ {
		pubKey := signerKeys[i].PubKey()

		signSet[i] = pubKey
	}

	var combinedKey *btcec.PublicKey

	var ctxOpts []musig2.ContextOption
	switch {
	case len(taprootTweak) == 0:
		ctxOpts = append(ctxOpts, musig2.WithBip86TweakCtx())
	case taprootTweak != nil:
		ctxOpts = append(ctxOpts, musig2.WithTaprootTweakCtx(taprootTweak))
	case len(tweaks) != 0:
		ctxOpts = append(ctxOpts, musig2.WithTweakedContext(tweaks...))
	}

	ctxOpts = append(ctxOpts, musig2.WithKnownSigners(signSet))

	// Now that we have all the signers, we'll make a new context, then
	// generate a new session for each of them(which handles nonce
	// generation).
	signers := make([]*musig2.Session, numSigners)
	for i, signerKey := range signerKeys {
		signCtx, err := musig2.NewContext(
			signerKey, false, ctxOpts...,
		)
		if err != nil {
			log.Fatalf("unable to generate context: %v", err)
		}

		if combinedKey == nil {
			combinedKey, err = signCtx.CombinedKey()
			if err != nil {
				log.Fatalf("combined key not available: %v", err)
			}
		}

		session, err := signCtx.NewSession()
		if err != nil {
			log.Fatalf("unable to generate new session: %v", err)
		}
		signers[i] = session
	}

	// Next, in the pre-signing phase, we'll send all the nonces to each
	// signer.
	var wg sync.WaitGroup
	for i, signCtx := range signers {
		signCtx := signCtx

		wg.Add(1)
		go func(idx int, signer *musig2.Session) {
			defer wg.Done()

			for j, otherCtx := range signers {
				if idx == j {
					continue
				}

				nonce := otherCtx.PublicNonce()
				haveAll, err := signer.RegisterPubNonce(nonce)
				if err != nil {
					log.Fatalf("unable to add public nonce")
				}

				if j == len(signers)-1 && !haveAll {
					log.Fatalf("all public nonces should have been detected")
				}
			}
		}(i, signCtx)
	}

	wg.Wait()

	// In the final step, we'll use the first signer as our combiner, and
	// generate a signature for each signer, and then accumulate that with
	// the combiner.
	combiner := signers[0]
	for i := range signers {
		signer := signers[i]
		partialSig, err := signer.Sign(msg)
		if err != nil {
			log.Fatalf("unable to generate partial sig: %v", err)
		}

		// We don't need to combine the signature for the very first
		// signer, as it already has that partial signature.
		if i != 0 {
			haveAll, err := combiner.CombineSig(partialSig)
			if err != nil {
				log.Fatalf("unable to combine sigs: %v", err)
			}

			if i == len(signers)-1 && !haveAll {
				log.Fatalf("final sig wasn't reconstructed")
			}
		}
	}

	// Finally we'll combined all the nonces, and ensure that it validates
	// as a single schnorr signature.
	finalSig := combiner.FinalSig()
	if !finalSig.Verify(msg[:], combinedKey) {
		log.Fatalf("final sig is invalid!")
	}

	// Verify that if we try to sign again with any of the existing
	// signers, then we'll get an error as the nonces have already been
	// used.
	for _, signer := range signers {
		_, err := signer.Sign(msg)
		if err != musig2.ErrSigningContextReuse {
			log.Fatalf("expected to get signing context reuse")
		}
	}

	return finalSig, combinedKey, msg[:], nil
}

func MultiPartyCombinedKey(signerKeys []*btcec.PrivateKey, taprootTweak []byte,
	tweaks ...musig2.KeyTweakDesc) (*btcec.PublicKey, error) {

	numSigners := len(signerKeys)

	// First generate the set of signers along with their public keys.
	// signerKeys := make([]*btcec.PrivateKey, numSigners)
	signSet := make([]*btcec.PublicKey, numSigners)
	for i := 0; i < numSigners; i++ {
		pubKey := signerKeys[i].PubKey()

		signSet[i] = pubKey
	}

	var combinedKey *btcec.PublicKey

	var ctxOpts []musig2.ContextOption
	switch {
	case len(taprootTweak) == 0:
		ctxOpts = append(ctxOpts, musig2.WithBip86TweakCtx())
	case taprootTweak != nil:
		ctxOpts = append(ctxOpts, musig2.WithTaprootTweakCtx(taprootTweak))
	case len(tweaks) != 0:
		ctxOpts = append(ctxOpts, musig2.WithTweakedContext(tweaks...))
	}

	ctxOpts = append(ctxOpts, musig2.WithKnownSigners(signSet))

	// Now that we have all the signers, we'll make a new context, then
	// generate a new session for each of them(which handles nonce
	// generation).
	signers := make([]*musig2.Session, numSigners)
	for i, signerKey := range signerKeys {
		signCtx, err := musig2.NewContext(
			signerKey, false, ctxOpts...,
		)
		if err != nil {
			log.Fatalf("unable to generate context: %v", err)
		}

		if combinedKey == nil {
			combinedKey, err = signCtx.CombinedKey()
			if err != nil {
				log.Fatalf("combined key not available: %v", err)
			}
		}

		session, err := signCtx.NewSession()
		if err != nil {
			log.Fatalf("unable to generate new session: %v", err)
		}
		signers[i] = session
	}
	return combinedKey, nil
}
