package ord

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

// PartyIDs returns a party.IDSlice (sorted) with IDs represented as simple strings.
func PartyIDs(n int) party.IDSlice {
	baseString := ""
	ids := make(party.IDSlice, n)
	for i := range ids {
		if i%26 == 0 && i > 0 {
			baseString += "a"
		}
		ids[i] = party.ID(baseString + string('a'+rune(i%26)))
	}
	return party.NewIDSlice(ids)
}

func ComputeTaprootOutputKey(internalKey *btcec.PublicKey,
	scriptRoot []byte) *btcec.PublicKey {

	// This routine only operates on x-only public keys where the public
	// key always has an even y coordinate, so we'll re-parse it as such.
	// internalKey, _ := schnorr.ParsePubKey(schnorr.SerializePubKey(pubKey))

	// First, we'll compute the tap tweak hash that commits to the internal
	// key and the merkle script root.
	tapTweakHash := chainhash.TaggedHash(
		chainhash.TagTapTweak, internalKey.SerializeCompressed(),
		scriptRoot,
	)

	// With the tap tweek computed,  we'll need to convert the merkle root
	// into something in the domain we can manipulate: a scalar value mod
	// N.
	var tweakScalar btcec.ModNScalar
	tweakScalar.SetBytes((*[32]byte)(tapTweakHash))

	// Next, we'll need to convert the internal key to jacobian coordinates
	// as the routines we need only operate on this type.
	var internalPoint btcec.JacobianPoint
	internalKey.AsJacobian(&internalPoint)

	// With our intermediate data obtained, we'll now compute:
	//
	// taprootKey = internalPoint + (tapTweak*G).
	var tPoint, taprootKey btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(&tweakScalar, &tPoint)
	btcec.AddNonConst(&internalPoint, &tPoint, &taprootKey)

	// Finally, we'll convert the key back to affine coordinates so we can
	// return the format of public key we usually use.
	taprootKey.ToAffine()

	return btcec.NewPublicKey(&taprootKey.X, &taprootKey.Y)
}
