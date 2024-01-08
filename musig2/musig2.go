package musig2

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
)

const (
	// MuSig2PartialSigSize is the size of a MuSig2 partial signature.
	// Because a partial signature is just the s value, this corresponds to
	// the length of a scalar.
	MuSig2PartialSigSize = 32
)

type MuSig2Context interface {
	// SigningKeys returns the set of keys used for signing.
	SigningKeys() []*btcec.PublicKey

	// CombinedKey returns the combined public key that will be used to
	// generate multi-signatures  against.
	CombinedKey() (*btcec.PublicKey, error)

	// TaprootInternalKey returns the internal taproot key, which is the
	// aggregated key _before_ the tweak is applied. If a taproot tweak was
	// specified, then CombinedKey() will return the fully tweaked output
	// key, with this method returning the internal key. If a taproot tweak
	// wasn't specified, then this method will return an error.
	TaprootInternalKey() (*btcec.PublicKey, error)
}

type MuSig2Session interface {
	// FinalSig returns the final combined multi-signature, if present.
	FinalSig() *schnorr.Signature

	// PublicNonce returns the public nonce for a signer. This should be
	// sent to other parties before signing begins, so they can compute the
	// aggregated public nonce.
	PublicNonce() [musig2.PubNonceSize]byte

	// NumRegisteredNonces returns the total number of nonces that have been
	// registered so far.
	NumRegisteredNonces() int

	// RegisterPubNonce should be called for each public nonce from the set
	// of signers. This method returns true once all the public nonces have
	// been accounted for.
	RegisterPubNonce(nonce [musig2.PubNonceSize]byte) (bool, error)
}

type MuSig2Tweaks struct {
	// GenericTweaks is a list of normal tweaks to apply to the combined
	// public key (and to the private key when signing).
	GenericTweaks []musig2.KeyTweakDesc

	// TaprootBIP0086Tweak indicates that the final key should use the
	// taproot tweak as defined in BIP 341, with the BIP 86 modification:
	//     outputKey = internalKey + h_tapTweak(internalKey)*G.
	// In this case, the aggregated key before the tweak will be used as the
	// internal key. If this is set to true then TaprootTweak will be
	// ignored.
	TaprootBIP0086Tweak bool

	// TaprootTweak specifies that the final key should use the taproot
	// tweak as defined in BIP 341:
	//     outputKey = internalKey + h_tapTweak(internalKey || scriptRoot).
	// In this case, the aggregated key before the tweak will be used as the
	// internal key. Will be ignored if TaprootBIP0086Tweak is set to true.
	TaprootTweak []byte
}

// ToContextOptions converts the tweak descriptor to context options.
func (t *MuSig2Tweaks) ToContextOptions() []musig2.ContextOption {
	var tweakOpts []musig2.ContextOption
	if len(t.GenericTweaks) > 0 {
		tweakOpts = append(tweakOpts, musig2.WithTweakedContext(
			t.GenericTweaks...,
		))
	}

	// The BIP0086 tweak and the taproot script tweak are mutually
	// exclusive.
	if t.TaprootBIP0086Tweak {
		tweakOpts = append(tweakOpts, musig2.WithBip86TweakCtx())
	} else if len(t.TaprootTweak) > 0 {
		tweakOpts = append(tweakOpts, musig2.WithTaprootTweakCtx(
			t.TaprootTweak,
		))
	}

	return tweakOpts
}
func MuSig2CombineKeys(allSignerPubKeys []*btcec.PublicKey, sortKeys bool,
	tweaks *MuSig2Tweaks) (*musig2.AggregateKey, error) {

	// Convert the tweak options into the appropriate MuSig2 API functional
	// options.
	var keyAggOpts []musig2.KeyAggOption
	switch {
	case tweaks.TaprootBIP0086Tweak:
		keyAggOpts = append(keyAggOpts, musig2.WithBIP86KeyTweak())
	case len(tweaks.TaprootTweak) > 0:
		keyAggOpts = append(keyAggOpts, musig2.WithTaprootKeyTweak(
			tweaks.TaprootTweak,
		))
	case len(tweaks.GenericTweaks) > 0:
		keyAggOpts = append(keyAggOpts, musig2.WithKeyTweaks(
			tweaks.GenericTweaks...,
		))
	}

	// Then we'll use this information to compute the aggregated public key.
	combinedKey, _, _, err := musig2.AggregateKeys(
		allSignerPubKeys, sortKeys, keyAggOpts...,
	)
	return combinedKey, err
}

func MuSig2CreateContext(privKey *btcec.PrivateKey,
	allSignerPubKeys []*btcec.PublicKey,
	tweaks *MuSig2Tweaks) (*musig2.Context, *musig2.Session, error) {

	// The context keeps track of all signing keys and our local key.
	allOpts := append(
		[]musig2.ContextOption{
			musig2.WithKnownSigners(allSignerPubKeys),
		},
		tweaks.ToContextOptions()...,
	)
	muSigContext, err := musig2.NewContext(privKey, true, allOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating MuSig2 signing "+
			"context: %v", err)
	}

	muSigSession, err := muSigContext.NewSession()
	if err != nil {
		return nil, nil, fmt.Errorf("error creating MuSig2 signing "+
			"session: %v", err)
	}

	return muSigContext, muSigSession, nil
}

// MuSig2Sign calls the Sign() method on the given versioned signing session and
// returns the result in the most recent version of the MuSig2 API.
func MuSig2Sign(session *musig2.Session, msg [32]byte,
	withSortedKeys bool) (*musig2.PartialSignature, error) {

	var opts []musig2.SignOption
	if withSortedKeys {
		opts = append(opts, musig2.WithSortedKeys())
	}
	partialSig, err := session.Sign(msg, opts...)
	if err != nil {
		return nil, fmt.Errorf("error signing with local key: "+
			"%v", err)
	}

	return partialSig, nil
}

// MuSig2CombineSig calls the CombineSig() method on the given versioned signing
// session and returns the result in the most recent version of the MuSig2 API.
func MuSig2CombineSig(session *musig2.Session,
	otherPartialSig *musig2.PartialSignature) (bool, error) {

	haveAllSigs, err := session.CombineSig(otherPartialSig)
	if err != nil {
		return false, fmt.Errorf("error combining partial "+
			"signature: %v", err)
	}

	return haveAllSigs, nil
}

func MuSig2FinalSig(session *musig2.Session) *schnorr.Signature {
	return session.FinalSig()
}

// SerializePartialSignature encodes the partial signature to a fixed size byte
// array.
func SerializePartialSignature(
	sig *musig2.PartialSignature) ([MuSig2PartialSigSize]byte, error) {

	var (
		buf    bytes.Buffer
		result [MuSig2PartialSigSize]byte
	)
	if err := sig.Encode(&buf); err != nil {
		return result, fmt.Errorf("error encoding partial signature: "+
			"%v", err)
	}

	if buf.Len() != MuSig2PartialSigSize {
		return result, fmt.Errorf("invalid partial signature length, "+
			"got %d wanted %d", buf.Len(), MuSig2PartialSigSize)
	}

	copy(result[:], buf.Bytes())

	return result, nil
}

// DeserializePartialSignature decodes a partial signature from a byte slice.
func DeserializePartialSignature(scalarBytes []byte) (*musig2.PartialSignature,
	error) {

	if len(scalarBytes) != MuSig2PartialSigSize {
		return nil, fmt.Errorf("invalid partial signature length, got "+
			"%d wanted %d", len(scalarBytes), MuSig2PartialSigSize)
	}

	sig := &musig2.PartialSignature{}
	if err := sig.Decode(bytes.NewReader(scalarBytes)); err != nil {
		return nil, fmt.Errorf("error decoding partial signature: %v",
			err)
	}

	return sig, nil
}
