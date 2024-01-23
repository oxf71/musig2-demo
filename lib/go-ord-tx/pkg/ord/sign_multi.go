package ord

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/oxf71/musig2-demo/musig2"
)

func TaprootWitnessSignatureMulti(tx *wire.MsgTx, sigHashes *txscript.TxSigHashes, idx int,
	amt int64, pkScript []byte, hashType txscript.SigHashType,
	key *btcec.PrivateKey, key2 *btcec.PrivateKey, controlBlockWitness []byte) (wire.TxWitness, error) {

	// As we're assuming this was a BIP 86 key, we use an empty root hash
	// which means output key commits to just the public key.
	fakeTapscriptRootHash := []byte{}

	sig, err := RawTxInTaprootSignatureMulti(
		tx, sigHashes, idx, amt, pkScript, fakeTapscriptRootHash,
		hashType, key, key2,
	)
	if err != nil {
		return nil, err
	}

	// The witness script to spend a taproot input using the key-spend path
	// is just the signature itself, given the public key is
	// embedded in the previous output script.
	if controlBlockWitness != nil {
		return wire.TxWitness{sig, controlBlockWitness}, nil
	}
	return wire.TxWitness{sig}, nil
}

func RawTxInTaprootSignatureMulti(tx *wire.MsgTx, sigHashes *txscript.TxSigHashes, idx int,
	amt int64, pkScript []byte, tapScriptRootHash []byte, hashType txscript.SigHashType,
	key *btcec.PrivateKey, key2 *btcec.PrivateKey) ([]byte, error) {

	// First, we'll start by compute the top-level taproot sighash.
	sigHash, err := txscript.CalcTaprootSignatureHash(
		sigHashes, hashType, tx, idx,
		txscript.NewCannedPrevOutputFetcher(pkScript, amt),
	)
	if err != nil {
		return nil, err
	}

	// Before we sign the sighash, we'll need to apply the taptweak to the
	// private key based on the tapScriptRootHash.
	privKeyTweak := TweakTaprootPrivKeyMulti(*key, tapScriptRootHash)
	privKeyTweak2 := TweakTaprootPrivKeyMulti(*key2, tapScriptRootHash)

	signature, _, err := musig2.TwoPrivSign2(privKeyTweak, privKeyTweak2, [32]byte(sigHash))

	// With the sighash constructed, we can sign it with the specified
	// private key.
	// signature, err := schnorr.Sign(privKeyTweak, sigHash)
	if err != nil {
		return nil, err
	}
	signature.Serialize()
	//TODO: gen tweak
	// signers := []*btcec.PrivateKey{privKeyTweak, privKeyTweak}
	// // taprootTweak := []byte{}
	// signature, _, _, err := musig2.MultiPartySign(signers, nil, [32]byte(sigHash))
	// if err != nil {
	// 	return nil, err
	// }

	sig := signature.Serialize()

	// If this is sighash default, then we can just return the signature
	// directly.
	if hashType&txscript.SigHashDefault == txscript.SigHashDefault {
		return sig, nil
	}

	// der, _ := hex.DecodeString("30440220")

	// fmt.Println("der", der)
	// finaleSig := append(der, sig...)
	// finaleSig = append(finaleSig, byte(hashType))

	// Otherwise, append the sighash type to the final sig.
	return append(sig, byte(hashType)), nil
}
func TweakTaprootPrivKeyMulti(privKey btcec.PrivateKey,
	scriptRoot []byte) *btcec.PrivateKey {

	// If the corresponding public key has an odd y coordinate, then we'll
	// negate the private key as specified in BIP 341.
	privKeyScalar := privKey.Key
	pubKeyBytes := privKey.PubKey().SerializeCompressed()
	if pubKeyBytes[0] == secp.PubKeyFormatCompressedOdd {
		privKeyScalar.Negate()
	}

	// Next, we'll compute the tap tweak hash that commits to the internal
	// key and the merkle script root. We'll snip off the extra parity byte
	// from the compressed serialization and use that directly.
	schnorrKeyBytes := pubKeyBytes[1:]
	tapTweakHash := chainhash.TaggedHash(
		chainhash.TagTapTweak, schnorrKeyBytes, scriptRoot,
	)

	// Map the private key to a ModNScalar which is needed to perform
	// operation mod the curve order.
	var tweakScalar btcec.ModNScalar
	tweakScalar.SetBytes((*[32]byte)(tapTweakHash))

	// Now that we have the private key in its may negated form, we'll add
	// the script root as a tweak. As we're using a ModNScalar all
	// operations are already normalized mod the curve order.
	privTweak := privKeyScalar.Add(&tweakScalar)

	return btcec.PrivKeyFromScalar(privTweak)
}

// func TaprootWitnessSignatureTest(tx *wire.MsgTx, sigHashes *txscript.TxSigHashes, idx int,
// 	amt int64, pkScript []byte, hashType txscript.SigHashType,
// 	key *btcec.PrivateKey) (*schnorr.Signature, error) {

// 	// As we're assuming this was a BIP 86 key, we use an empty root hash
// 	// which means output key commits to just the public key.
// 	fakeTapscriptRootHash := []byte{}

// 	return RawTxInTaprootSignatureTest(
// 		tx, sigHashes, idx, amt, pkScript, fakeTapscriptRootHash,
// 		hashType, key,
// 	)

// }
// func signSegWitV0(tx *wire.MsgTx, sigHashes *txscript.TxSigHashes, idx int,
// 	amt int64, pkScript []byte, hashType txscript.SigHashType,
// 	key *btcec.PrivateKey) ([]byte, error) {

// 	// We have everything we need for signing the input now.
// 	sig, err := txscript.RawTxInWitnessSignature(
// 		tx, sigHashes, idx, amt, pkScript,
// 		hashType, key,
// 	)

// 	if err != nil {
// 		return nil, fmt.Errorf("error signing input %d: %v", idx, err)
// 	}

// 	return sig, nil
// }
// func RawTxInTaprootSignatureTest(tx *wire.MsgTx, sigHashes *txscript.TxSigHashes, idx int,
// 	amt int64, pkScript []byte, tapScriptRootHash []byte, hashType txscript.SigHashType,
// 	key *btcec.PrivateKey) (*schnorr.Signature, error) {

// 	// First, we'll start by compute the top-level taproot sighash.
// 	sigHash, err := txscript.CalcTaprootSignatureHash(
// 		sigHashes, hashType, tx, idx,
// 		txscript.NewCannedPrevOutputFetcher(pkScript, amt),
// 	)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Before we sign the sighash, we'll need to apply the taptweak to the
// 	// private key based on the tapScriptRootHash.
// 	privKeyTweak := TweakTaprootPrivKey(*key, tapScriptRootHash)

// 	// With the sighash constructed, we can sign it with the specified
// 	// private key.
// 	signature, err := schnorr.Sign(privKeyTweak, sigHash)
// 	if err != nil {
// 		return nil, err
// 	}
// 	//TODO: gen tweak
// 	// signers := []*btcec.PrivateKey{privKeyTweak, privKeyTweak}
// 	// // taprootTweak := []byte{}
// 	// signature, _, _, err := musig2.MultiPartySign(signers, nil, [32]byte(sigHash))
// 	// if err != nil {
// 	// 	return nil, err
// 	// }

// 	return signature, nil

// }

// // RawTxInSignature returns the serialized ECDSA signature for the input idx of
// // the given transaction, with hashType appended to it.
// func RawTxInSignature(tx *wire.MsgTx, idx int, subScript []byte,
// 	hashType txscript.SigHashType, key *btcec.PrivateKey) ([]byte, error) {

// 	hash, err := txscript.CalcSignatureHash(subScript, hashType, tx, idx)
// 	if err != nil {
// 		return nil, err
// 	}
// 	signature := ecdsa.Sign(key, hash)

// 	return signature.Serialize(), nil
// }
// func WitnessSignature(tx *wire.MsgTx, sigHashes *txscript.TxSigHashes, idx int, amt int64,
// 	subscript []byte, hashType txscript.SigHashType, privKey *btcec.PrivateKey,
// 	compress bool) ([]byte, error) {

// 	sig, err := txscript.RawTxInWitnessSignature(tx, sigHashes, idx, amt, subscript,
// 		hashType, privKey)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return sig, nil

// 	// pk := privKey.PubKey()
// 	// var pkData []byte
// 	// if compress {
// 	// 	pkData = pk.SerializeCompressed()
// 	// } else {
// 	// 	pkData = pk.SerializeUncompressed()
// 	// }

// 	// // A witness script is actually a stack, so we return an array of byte
// 	// // slices here, rather than a single byte slice.
// 	// return wire.TxWitness{sig, pkData}, nil
// }
