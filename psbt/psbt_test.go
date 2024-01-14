package psbt_test

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/oxf71/musig2-demo/psbt"
)

func decodeHex(hexStr string) []byte {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		panic("invalid hex string in test source: err " + err.Error() +
			", hex: " + hexStr)
	}

	return b
}

// defaultDBTimeout specifies the timeout value when opening the wallet
// database.
var defaultDBTimeout = 10 * time.Second

// testWallet creates a test wallet and unlocks it.

func TestMultiAddress(t *testing.T) {
	_, publicKey1 := btcec.PrivKeyFromBytes(decodeHex("440bb3ec56d213e90d006d344d74f6478db4f7fa4cdd388095d8f4edef0c5156"))
	_, publicKey2 := btcec.PrivKeyFromBytes(decodeHex("e0087817fd1d1154a781c11b394a0dcec82f076bbf026df9d61667ead16fa778"))
	_, publicKey3 := btcec.PrivKeyFromBytes(decodeHex("e0087817fd1d1154a781c11b394a0dcec82f076bbf026df9d61667ead16fa771"))

	publicKey1Hex := hex.EncodeToString(publicKey1.SerializeCompressed())
	publicKey2Hex := hex.EncodeToString(publicKey2.SerializeCompressed())
	publicKey3Hex := hex.EncodeToString(publicKey3.SerializeCompressed())

	allSignerPubKeys := []string{publicKey1Hex, publicKey2Hex, publicKey3Hex}
	// gen 2-3 multi address
	multiSigScript, err := psbt.GetRedeemScript(allSignerPubKeys, 2)
	if err != nil {
		t.Error(err)
	}

	multiAddress, err := psbt.GenerateMultiAddress(multiSigScript, &chaincfg.TestNet3Params)
	if err != nil {
		t.Error(err)
	}

	fmt.Println(multiAddress)

	t.Fail()

}

func TestMultiTaprootAddress(t *testing.T) {
	_, publicKey1 := btcec.PrivKeyFromBytes(decodeHex("440bb3ec56d213e90d006d344d74f6478db4f7fa4cdd388095d8f4edef0c5156"))
	_, publicKey2 := btcec.PrivKeyFromBytes(decodeHex("e0087817fd1d1154a781c11b394a0dcec82f076bbf026df9d61667ead16fa778"))
	_, publicKey3 := btcec.PrivKeyFromBytes(decodeHex("e0087817fd1d1154a781c11b394a0dcec82f076bbf026df9d61667ead16fa771"))

	publicKey1Hex := hex.EncodeToString(publicKey1.SerializeCompressed())
	publicKey2Hex := hex.EncodeToString(publicKey2.SerializeCompressed())
	publicKey3Hex := hex.EncodeToString(publicKey3.SerializeCompressed())

	allSignerPubKeys := []string{publicKey1Hex, publicKey2Hex, publicKey3Hex}
	// gen 2-3 multi address

	multiTaprootAddress, _, err := psbt.GenerateMultiTaprootAddress(allSignerPubKeys, 2, &chaincfg.TestNet3Params)
	if err != nil {
		t.Error(err)
	}

	fmt.Println(multiTaprootAddress)

	t.Fail()

}
