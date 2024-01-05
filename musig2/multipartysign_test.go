package musig2_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
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

func TestMultiPartySign(t *testing.T) {

	privKey1, _ := btcec.PrivKeyFromBytes(decodeHex("440bb3ec56d213e90d006d344d74f6478db4f7fa4cdd388095d8f4edef0c5156"))
	privKey2, _ := btcec.PrivKeyFromBytes(decodeHex("e0087817fd1d1154a781c11b394a0dcec82f076bbf026df9d61667ead16fa778"))
	testTweak := [32]byte{
		0xE8, 0xF7, 0x91, 0xFF, 0x92, 0x25, 0xA2, 0xAF,
		0x01, 0x02, 0xAF, 0xFF, 0x4A, 0x9A, 0x72, 0x3D,
		0x96, 0x12, 0xA6, 0x82, 0xA2, 0x5E, 0xBE, 0x79,
		0x80, 0x2B, 0x26, 0x3C, 0xDF, 0xCD, 0x83, 0xBB,
	}

	priv := []*btcec.PrivateKey{privKey1, privKey2}

	sign, combinedKey, hash, err := musig2demo.MultiPartySign(priv, testTweak[:], []byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(hex.EncodeToString(combinedKey.SerializeCompressed()))

	if !sign.Verify(hash, combinedKey) {
		t.Fatal("signature does not verify")
	}
}
func TestMultiPartyCombinedKey(t *testing.T) {

	privKey1, _ := btcec.PrivKeyFromBytes(decodeHex("440bb3ec56d213e90d006d344d74f6478db4f7fa4cdd388095d8f4edef0c5156"))
	privKey2, _ := btcec.PrivKeyFromBytes(decodeHex("e0087817fd1d1154a781c11b394a0dcec82f076bbf026df9d61667ead16fa778"))
	testTweak := [32]byte{
		0xE8, 0xF7, 0x91, 0xFF, 0x92, 0x25, 0xA2, 0xAF,
		0x01, 0x02, 0xAF, 0xFF, 0x4A, 0x9A, 0x72, 0x3D,
		0x96, 0x12, 0xA6, 0x82, 0xA2, 0x5E, 0xBE, 0x79,
		0x80, 0x2B, 0x26, 0x3C, 0xDF, 0xCD, 0x83, 0xBB,
	}

	priv := []*btcec.PrivateKey{privKey1, privKey2}

	combinedKey, err := musig2demo.MultiPartyCombinedKey(priv, testTweak[:])
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(hex.EncodeToString(combinedKey.SerializeCompressed()))

}
