package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	musig2demo "github.com/oxf71/musig2-demo/musig2"
)

func decodeHex(hexStr string) []byte {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		panic("invalid hex string in test source: err " + err.Error() +
			", hex: " + hexStr)
	}

	return b
}

func main() {
	privKey1, publicKey1 := btcec.PrivKeyFromBytes(decodeHex("440bb3ec56d213e90d006d344d74f6478db4f7fa4cdd388095d8f4edef0c5156"))
	privKey2, publicKey2 := btcec.PrivKeyFromBytes(decodeHex("e0087817fd1d1154a781c11b394a0dcec82f076bbf026df9d61667ead16fa778"))
	privKey3, publicKey3 := btcec.PrivKeyFromBytes(decodeHex("e0087817fd1d1154a781c11b394a0dcec82f076bbf026df9d61667ead16fa771"))
	testTweak := [32]byte{
		0xE8, 0xF7, 0x91, 0xFF, 0x92, 0x25, 0xA2, 0xAF,
		0x01, 0x02, 0xAF, 0xFF, 0x4A, 0x9A, 0x72, 0x3D,
		0x96, 0x12, 0xA6, 0x82, 0xA2, 0x5E, 0xBE, 0x79,
		0x80, 0x2B, 0x26, 0x3C, 0xDF, 0xCD, 0x83, 0xBB,
	}

	allSignerPubKeys := []*btcec.PublicKey{publicKey1, publicKey2, publicKey3}

	muSig2Tweaks := musig2demo.MuSig2Tweaks{
		TaprootBIP0086Tweak: false,
		TaprootTweak:        testTweak[:],
		GenericTweaks:       []musig2.KeyTweakDesc{},
	}

	// sign msg
	msg := sha256.Sum256([]byte("msg hello"))
	nonce1chan := make(chan [musig2.PubNonceSize]byte, 10)
	nonce2chan := make(chan [musig2.PubNonceSize]byte, 10)
	nonce3chan := make(chan [musig2.PubNonceSize]byte, 10)
	partialSignature2 := make(chan musig2.PartialSignature)
	partialSignature3 := make(chan musig2.PartialSignature)
	finalSig := make(chan schnorr.Signature)

	go func() {
		// priv1
		_, session1, err := musig2demo.MuSig2CreateContext(privKey1, allSignerPubKeys, &muSig2Tweaks)
		if err != nil {
			fmt.Println(err)
			return
		}
		nonce1 := session1.PublicNonce()

		nonce1chan <- nonce1
		nonce1chan <- nonce1

		nonce2 := <-nonce2chan
		nonce3 := <-nonce3chan
		_, err = session1.RegisterPubNonce(nonce2)
		if err != nil {
			fmt.Println(err)
			return
		}

		_, err = session1.RegisterPubNonce(nonce3)
		if err != nil {
			log.Fatal(err)
		}

		_, err = musig2demo.MuSig2Sign(session1, msg, false)
		if err != nil {
			fmt.Println(err)
			return
		}
		partial2 := <-partialSignature2
		partial3 := <-partialSignature3

		_, err = musig2demo.MuSig2CombineSig(session1, &partial2)
		if err != nil {
			fmt.Println(err)
			return
		}

		_, err = musig2demo.MuSig2CombineSig(session1, &partial3)
		if err != nil {
			log.Fatal(err)
		}

		finalSig <- *musig2demo.MuSig2FinalSig(session1)
	}()

	go func() {
		// priv2
		_, session2, err := musig2demo.MuSig2CreateContext(privKey2, allSignerPubKeys, &muSig2Tweaks)
		if err != nil {
			fmt.Println(err)
			return
		}
		nonce2 := session2.PublicNonce()

		nonce2chan <- nonce2
		nonce2chan <- nonce2

		nonce1 := <-nonce1chan
		nonce3 := <-nonce3chan
		_, err = session2.RegisterPubNonce(nonce1)
		if err != nil {
			fmt.Println(err)
			return
		}

		_, err = session2.RegisterPubNonce(nonce3)
		if err != nil {
			log.Fatal(err)
		}

		partial2, err := musig2demo.MuSig2Sign(session2, msg, false)
		if err != nil {
			fmt.Println(err)
			return
		}

		partialSignature2 <- *partial2
	}()

	go func() {
		// priv3
		_, session3, err := musig2demo.MuSig2CreateContext(privKey3, allSignerPubKeys, &muSig2Tweaks)
		if err != nil {
			fmt.Println(err)
			return
		}
		nonce3 := session3.PublicNonce()
		nonce3chan <- nonce3
		nonce3chan <- nonce3

		nonce1 := <-nonce1chan
		nonce2 := <-nonce2chan
		_, err = session3.RegisterPubNonce(nonce1)
		if err != nil {
			fmt.Println(err)
			return
		}

		_, err = session3.RegisterPubNonce(nonce2)
		if err != nil {
			fmt.Println(err)
			return
		}

		partial3, err := musig2demo.MuSig2Sign(session3, msg, false)
		if err != nil {
			fmt.Println(err)
			return
		}

		partialSignature3 <- *partial3
	}()

	sig := <-finalSig

	combinedKey, err := musig2demo.MuSig2CombineKeys(allSignerPubKeys, false, &muSig2Tweaks)
	if err != nil {
		log.Fatal(err)
	}
	if !sig.Verify(msg[:], combinedKey.FinalKey) {
		log.Fatal("invalid signature")
	}

	fmt.Println("combinedKey:", hex.EncodeToString(combinedKey.FinalKey.SerializeCompressed()))
	fmt.Println("sig:", hex.EncodeToString(sig.Serialize()))

}
