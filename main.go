package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	// "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	musig2demo "github.com/oxf71/musig2-demo/musig2"
)

type bip340Test struct {
	secretKey    string
	publicKey    string
	auxRand      string
	message      string
	signature    string
	verifyResult bool
	validPubKey  bool
	expectErr    error
	rfc6979      bool
}

var bip340TestVectors = []bip340Test{
	{
		secretKey: "440bb3ec56d213e90d006d344d74f6478db4f7fa4cdd388095d8f4edef0c5156",
		publicKey: "03d7ce6683d188fe474d0099fc1035017761be40f7a6c50f3b2f459e1c128eac6a",
	},
	{
		secretKey: "e0087817fd1d1154a781c11b394a0dcec82f076bbf026df9d61667ead16fa778",
		publicKey: "03f07fc321723c0516f524315470c32aa54a0150bffb8bee113334e5b1e356563d", // mycjLUFZ1Lo4GwaXoB9RAVFnG81AJGQy2a
	},
}

func decodeHex(hexStr string) []byte {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		panic("invalid hex string in test source: err " + err.Error() +
			", hex: " + hexStr)
	}

	return b
}

func sign() {

	test := bip340TestVectors[0]

	d := decodeHex(test.secretKey)
	privKey, _ := btcec.PrivKeyFromBytes(d)

	var auxBytes [32]byte
	aux := decodeHex(test.auxRand)
	copy(auxBytes[:], aux)

	msg := decodeHex(test.message)

	fmt.Println("publicKey:", string(privKey.PubKey().SerializeCompressed()))

	sig, err := schnorr.Sign(privKey, msg)
	if err != nil {
		log.Fatal(err)
	}

	sigStr := strings.ToUpper(hex.EncodeToString(sig.Serialize()))

	fmt.Println(sigStr)
}

func verify() {
	// privKey, err := btcec.NewPrivateKey()
	// if err != nil {
	// 	log.Fatalf("unable to gen priv key: %v", err)
	// }

	// pubKey := privKey.PubKey()

	// pk := hex.EncodeToString(privKey.Serialize())

	// pubK := hex.EncodeToString(pubKey.SerializeCompressed())
	// address, err := btcutil.NewAddressPubKey(pubKey.SerializeCompressed(), &chaincfg.TestNet3Params)
	// if err != nil {
	// 	log.Fatalf("unable to gen pub key: %v", err)
	// }
	// fmt.Println(pk)
	// fmt.Println(pubK)
	// fmt.Println(address.EncodeAddress())

	var combinedKey *btcec.PublicKey
	signerKeys := make([]*btcec.PrivateKey, len(bip340TestVectors))
	signSet := make([]*btcec.PublicKey, len(bip340TestVectors))
	for i, v := range bip340TestVectors {
		d := decodeHex(v.secretKey)
		privKey, _ := btcec.PrivKeyFromBytes(d)

		pubKey := privKey.PubKey()

		signerKeys[i] = privKey
		signSet[i] = pubKey
	}
	var ctxOpts []musig2.ContextOption
	// taprootTweak := [32]byte{
	// 	0xE8, 0xF7, 0x91, 0xFF, 0x92, 0x25, 0xA2, 0xAF,
	// 	0x01, 0x02, 0xAF, 0xFF, 0x4A, 0x9A, 0x72, 0x3D,
	// 	0x96, 0x12, 0xA6, 0x82, 0xA2, 0x5E, 0xBE, 0x79,
	// 	0x80, 0x2B, 0x26, 0x3C, 0xDF, 0xCD, 0x83, 0xBB,
	// }
	// // // taprootTweak := musig2.KeyTweakDesc{
	// // // 	Tweak:   testTweak,
	// // // 	IsXOnly: true,
	// // // }
	// // taprootTweak := []byte{}

	// switch {
	// case len(taprootTweak) == 0:
	// 	ctxOpts = append(ctxOpts, musig2.WithBip86TweakCtx())
	// case taprootTweak[:] != nil:
	// 	ctxOpts = append(ctxOpts, musig2.WithTaprootTweakCtx(taprootTweak[:]))
	// 	// case len(tweaks) != 0:
	// 	// 	ctxOpts = append(ctxOpts, musig2.WithTweakedContext(tweaks...))
	// }

	ctxOpts = append(ctxOpts, musig2.WithKnownSigners(signSet))
	signers := make([]*musig2.Session, 2)
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
	combined := hex.EncodeToString(combinedKey.SerializeCompressed())
	combinedAddress, err := btcutil.NewAddressPubKey(combinedKey.SerializeCompressed(), &chaincfg.TestNet3Params)
	if err != nil {
		log.Fatalf("unable to gen pub key: %v", err)
	}
	fmt.Println("combined: ", combined)
	fmt.Println("combined address: ", combinedAddress.EncodeAddress())
	utxoTaprootAddress, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(combinedKey)), &chaincfg.TestNet3Params)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("utxo taproot address: ", utxoTaprootAddress.EncodeAddress())
}

func musig2_demo() {
	// 聚合签名 pub key
	var combinedKey *btcec.PublicKey

	// 私钥1
	privKey1, _ := btcec.PrivKeyFromBytes(decodeHex(bip340TestVectors[0].secretKey))
	pubKey1 := privKey1.PubKey()

	// 私钥2
	privKey2, _ := btcec.PrivKeyFromBytes(decodeHex(bip340TestVectors[1].secretKey))
	pubKey2 := privKey2.PubKey()

	signSet := make([]*btcec.PublicKey, len(bip340TestVectors))
	signSet = append(signSet, pubKey1, pubKey2)

	//
	var ctxOpts []musig2.ContextOption
	ctxOpts = append(ctxOpts, musig2.WithKnownSigners(signSet))
	ctxOpts = append(ctxOpts, musig2.WithBip86TweakCtx())
	fmt.Println(ctxOpts)

	signCtx1, err := musig2.NewContext(
		privKey1, false, ctxOpts...,
	)
	if err != nil {
		log.Fatalf("unable to generate context: %v", err)
	}
	if combinedKey == nil {
		combinedKey, err = signCtx1.CombinedKey()
		if err != nil {
			log.Fatalf("combined key not available: %v", err)
		}
	}
	session1, err := signCtx1.NewSession()
	if err != nil {
		log.Fatalf("unable to generate new session: %v", err)
	}

	session2, err := session(privKey2, combinedKey, ctxOpts...)
	if err != nil {
		log.Fatalf("unable to generate new session: %v", err)
	}

	combined := hex.EncodeToString(combinedKey.SerializeCompressed())
	combinedAddress, err := btcutil.NewAddressPubKey(combinedKey.SerializeCompressed(), &chaincfg.TestNet3Params)
	if err != nil {
		log.Fatalf("unable to gen pub key: %v", err)
	}
	fmt.Println("combined: ", combined)
	fmt.Println("combined address: ", combinedAddress.EncodeAddress())
	utxoTaprootAddress, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(combinedKey)), &chaincfg.TestNet3Params)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("utxo taproot address: ", utxoTaprootAddress.EncodeAddress())

	signers := make([]*musig2.Session, 2)
	signers = append(signers, session1, session2)
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

	msg := sha256.Sum256([]byte("let's get taprooty"))

	_, err = session1.Sign(msg)
	if err != nil {
		log.Fatalf("unable to generate partial sig: %v", err)
	}

	partialSig2, err := session2.Sign(msg)
	if err != nil {
		log.Fatalf("unable to generate partial sig: %v", err)
	}

	haveAll, err := session1.CombineSig(partialSig2)
	if err != nil {
		log.Fatalf("unable to combine sigs: %v", err)
	}
	if !haveAll {
		log.Fatalf("final sig wasn't reconstructed")
	}

}
func musig2_early_demo() {
	//  btcec.PrivKeyFromBytes(decodeHex(bip340TestVectors[0].secretKey))
	privKey1, _ := btcec.PrivKeyFromBytes(decodeHex(bip340TestVectors[0].secretKey))
	privKey2, _ := btcec.PrivKeyFromBytes(decodeHex(bip340TestVectors[0].secretKey))

	// privKey1, err := btcec.NewPrivateKey()
	// if err != nil {
	// 	log.Fatalf("unable to gen priv key: %v", err)
	// }
	// privKey2, err := btcec.NewPrivateKey()
	// if err != nil {
	// 	log.Fatalf("unable to gen priv key: %v", err)
	// }

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

	msg := sha256.Sum256([]byte("let's get taprooty, LN style"))

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

	// Finally, verify that the final signature is valid.
	combinedKey, err := ctx1.CombinedKey()
	if err != nil {
		log.Fatalf("unexpected combined key error: %v", err)
	}
	finalSig := session1.FinalSig()
	if !finalSig.Verify(msg[:], combinedKey) {
		log.Fatalf("final sig is invalid!")
	}

	combined := hex.EncodeToString(combinedKey.SerializeCompressed())
	combinedAddress, err := btcutil.NewAddressPubKey(combinedKey.SerializeCompressed(), &chaincfg.TestNet3Params)
	if err != nil {
		log.Fatalf("unable to gen pub key: %v", err)
	}
	fmt.Println("combined: ", combined)
	fmt.Println("combined address: ", combinedAddress.EncodeAddress())
	utxoTaprootAddress, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(combinedKey)), &chaincfg.TestNet3Params)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("utxo taproot address: ", utxoTaprootAddress.EncodeAddress())
	fmt.Println("finalSig: ", hex.EncodeToString(finalSig.Serialize()))
}

func session(privKey *btcec.PrivateKey, combinedKey *btcec.PublicKey, ctxOpts ...musig2.ContextOption) (*musig2.Session, error) {
	signCtx2, err := musig2.NewContext(
		privKey, false, ctxOpts...,
	)
	if err != nil {
		log.Fatalf("unable to generate context: %v", err)
	}
	if combinedKey == nil {
		combinedKey, err = signCtx2.CombinedKey()
		if err != nil {
			log.Fatalf("combined key not available: %v", err)
		}
	}
	return signCtx2.NewSession()
}

func RawTxInSignature(tx *wire.MsgTx, idx int, subScript []byte,
	hashType txscript.SigHashType, key1 *btcec.PrivateKey, key2 *btcec.PrivateKey) ([]byte, error) {

	hash, err := txscript.CalcSignatureHash(subScript, hashType, tx, idx)
	if err != nil {
		return nil, err
	}

	// signature := ecdsa.Sign(key1, hash)
	signature, hash, err := musig2demo.TwoPrivSign2(key1, key2, hash)
	if err != nil {
		log.Fatal(err)
	}

	return append(signature.Serialize(), byte(hashType)), nil
}

func SignatureScript(tx *wire.MsgTx, idx int, subscript []byte, hashType txscript.SigHashType, privKey1 *btcec.PrivateKey, privKey2 *btcec.PrivateKey, compress bool) ([]byte, error) {
	sig, err := RawTxInSignature(tx, idx, subscript, hashType, privKey1, privKey2)
	if err != nil {
		return nil, err
	}

	pk, err := musig2demo.TwoCombinedKey(privKey1, privKey2)
	if err != nil {
		log.Fatal(err)
	}

	// pk := privKey.PubKey()
	var pkData []byte
	if compress {
		pkData = pk.SerializeCompressed()
	} else {
		pkData = pk.SerializeUncompressed()
	}

	return txscript.NewScriptBuilder().AddData(sig).AddData(pkData).Script()
}

func main() {

	// sendTransaction()

	privKey1, _ := btcec.PrivKeyFromBytes(decodeHex(bip340TestVectors[0].secretKey))
	privKey2, _ := btcec.PrivKeyFromBytes(decodeHex(bip340TestVectors[1].secretKey))

	musig2_early_demo()
	msg := []byte("msg hello")
	sign, hash, err := musig2demo.TwoPrivSign2(privKey1, privKey2, msg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("sign: ", hex.EncodeToString(sign.Serialize()))
	fmt.Println("sign hash", hex.EncodeToString(hash))

	btcAddress := musig2demo.TwoBtcAddress(privKey1, privKey2)
	fmt.Println("btcAddress: ", btcAddress)

	taprootAddress := musig2demo.TwoBtcTaprootAddress(privKey1, privKey2)
	fmt.Println("taprootAddress: ", taprootAddress)

	// verify sign

	combinedKey, err := musig2demo.TwoCombinedKey(privKey1, privKey2)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("combinedKey", combinedKey.SerializeCompressed())

	fmt.Println("sign verify: ", sign.Verify(hash, combinedKey))
}
