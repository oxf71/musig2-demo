package psbt

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/txscript"

	"github.com/btcsuite/btcd/chaincfg"
)

func GetRedeemScript(pubKeys []string, minSignNum int) ([]byte, error) {
	var allPubKeys []*btcutil.AddressPubKey
	for _, v := range pubKeys {
		pubKey, err := hex.DecodeString(v)
		if err != nil {
			return nil, err
		}
		addressPubKey, err := btcutil.NewAddressPubKey(pubKey, &chaincfg.TestNet3Params)

		if err != nil {
			return nil, err
		}
		allPubKeys = append(allPubKeys, addressPubKey)
	}
	return txscript.MultiSigScript(allPubKeys, minSignNum)
}

func GenerateMultiAddress(redeemScript []byte, net *chaincfg.Params) (string, error) {
	if net == nil {
		net = &chaincfg.TestNet3Params
	}
	addressScriptHash, err := btcutil.NewAddressScriptHash(redeemScript, net)
	if err != nil {
		return "", err
	}
	P2WSHAddress := base58.CheckEncode(addressScriptHash.ScriptAddress(), net.WitnessScriptHashAddrID)
	return P2WSHAddress, nil
}

func GenerateMultiTaprootAddress(pubKeys []string, minSignNum int, net *chaincfg.Params) (string, []byte, error) {
	var allPubKeys []*btcutil.AddressPubKey
	for _, v := range pubKeys {
		pubKey, err := hex.DecodeString(v)
		if err != nil {
			return "", nil, err
		}
		addressPubKey, err := btcutil.NewAddressPubKey(pubKey, &chaincfg.TestNet3Params)
		if err != nil {
			return "", nil, err
		}
		allPubKeys = append(allPubKeys, addressPubKey)
	}

	builder := txscript.NewScriptBuilder()
	builder.AddInt64(int64(minSignNum))
	for _, key := range allPubKeys {
		builder.AddData(key.ScriptAddress())
	}
	builder.AddInt64(int64(len(allPubKeys)))
	builder.AddOp(txscript.OP_CHECKMULTISIG)

	witnessScript, err := builder.Script()
	if err != nil {
		return "", nil, err
	}
	h256 := sha256.Sum256(witnessScript)
	witnessProg := h256[:]
	address, err := btcutil.NewAddressWitnessScriptHash(witnessProg, net)
	if err != nil {
		return "", nil, err
	}
	return address.EncodeAddress(), witnessScript, nil
}
