package musig2_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	musig2demo "github.com/oxf71/musig2-demo/musig2"
)

func TestMuSig2CombineKeys(t *testing.T) {
	_, publicKey1 := btcec.PrivKeyFromBytes(decodeHex("440bb3ec56d213e90d006d344d74f6478db4f7fa4cdd388095d8f4edef0c5156"))
	_, publicKey2 := btcec.PrivKeyFromBytes(decodeHex("e0087817fd1d1154a781c11b394a0dcec82f076bbf026df9d61667ead16fa778"))
	_ = [32]byte{
		0xE8, 0xF7, 0x91, 0xFF, 0x92, 0x25, 0xA2, 0xAF,
		0x01, 0x02, 0xAF, 0xFF, 0x4A, 0x9A, 0x72, 0x3D,
		0x96, 0x12, 0xA6, 0x82, 0xA2, 0x5E, 0xBE, 0x79,
		0x80, 0x2B, 0x26, 0x3C, 0xDF, 0xCD, 0x83, 0xBB,
	}

	allSignerPubKeys := []*btcec.PublicKey{publicKey1, publicKey2}

	muSig2Tweaks := musig2demo.MuSig2Tweaks{
		TaprootBIP0086Tweak: false,
		// TaprootTweak:        testTweak[:],
		GenericTweaks: []musig2.KeyTweakDesc{},
	}

	combinedKey, err := musig2demo.MuSig2CombineKeys(allSignerPubKeys, false, &muSig2Tweaks)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(hex.EncodeToString(combinedKey.FinalKey.SerializeCompressed()))

	t.Fail()
}

func TestMusig2Sign(t *testing.T) {
	privKey1, publicKey1 := btcec.PrivKeyFromBytes(decodeHex("440bb3ec56d213e90d006d344d74f6478db4f7fa4cdd388095d8f4edef0c5156"))
	privKey2, publicKey2 := btcec.PrivKeyFromBytes(decodeHex("e0087817fd1d1154a781c11b394a0dcec82f076bbf026df9d61667ead16fa778"))
	_ = [32]byte{
		0xE8, 0xF7, 0x91, 0xFF, 0x92, 0x25, 0xA2, 0xAF,
		0x01, 0x02, 0xAF, 0xFF, 0x4A, 0x9A, 0x72, 0x3D,
		0x96, 0x12, 0xA6, 0x82, 0xA2, 0x5E, 0xBE, 0x79,
		0x80, 0x2B, 0x26, 0x3C, 0xDF, 0xCD, 0x83, 0xBB,
	}

	allSignerPubKeys := []*btcec.PublicKey{publicKey1, publicKey2}

	muSig2Tweaks := musig2demo.MuSig2Tweaks{
		TaprootBIP0086Tweak: false,
		// TaprootTweak:        testTweak[:],
		GenericTweaks: []musig2.KeyTweakDesc{},
	}

	// sign msg
	msg := sha256.Sum256([]byte("msg hello"))
	nonce2chan := make(chan [musig2.PubNonceSize]byte, 10)
	nonce1chan := make(chan [musig2.PubNonceSize]byte, 10)
	partialSignature2 := make(chan musig2.PartialSignature)
	finalSig := make(chan schnorr.Signature, 10)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		// priv1
		_, session1, err := musig2demo.MuSig2CreateContext(privKey1, allSignerPubKeys, &muSig2Tweaks)
		if err != nil {
			t.Fatal(err)
		}
		nonce1 := session1.PublicNonce()

		nonce1chan <- nonce1

		nonce2 := <-nonce2chan
		_, err = session1.RegisterPubNonce(nonce2)
		if err != nil {
			t.Fatal(err)
		}

		_, err = musig2demo.MuSig2Sign(session1, msg, false)
		if err != nil {
			t.Fatal(err)
		}
		partial2 := <-partialSignature2

		_, err = musig2demo.MuSig2CombineSig(session1, &partial2)
		if err != nil {
			t.Fatal(err)
		}
		finalSig <- *musig2demo.MuSig2FinalSig(session1)
	}()

	go func() {
		// priv2
		_, session2, err := musig2demo.MuSig2CreateContext(privKey2, allSignerPubKeys, &muSig2Tweaks)
		if err != nil {
			t.Fatal(err)
		}
		nonce2 := session2.PublicNonce()

		nonce2chan <- nonce2

		nonce1 := <-nonce1chan
		_, err = session2.RegisterPubNonce(nonce1)
		if err != nil {
			t.Fatal(err)
		}

		partial2, err := musig2demo.MuSig2Sign(session2, msg, false)
		if err != nil {
			t.Fatal(err)
		}

		partialSignature2 <- *partial2
		wg.Done()
	}()
	wg.Wait()

	sig := <-finalSig

	combinedKey, err := musig2demo.MuSig2CombineKeys(allSignerPubKeys, false, &muSig2Tweaks)
	if err != nil {
		t.Fatal(err)
	}
	if !sig.Verify(msg[:], combinedKey.FinalKey) {
		t.Fatal("invalid signature")
	}

	fmt.Println("combinedKey:", hex.EncodeToString(combinedKey.FinalKey.SerializeCompressed()))
	fmt.Println("sig:", hex.EncodeToString(sig.Serialize()))

	// t.Fail()
}
