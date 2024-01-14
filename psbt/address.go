package psbt

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

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
	// 设置多签公钥
	// publicKeysHex := []string{
	// 	"035f9a9c84d8b9d9b187c266e2d6e000cc2abf6f20faea7d0b0a9a4e2b9d4d9a7f",
	// 	"03e0c9e9b5b6e9e6c4e8a8b5e9b5e9b5e9b5e9b5e9b5e9b5e9b5e9b5e9b5e9b5e",
	// 	"02e8e1e6e5e5e9e7e7e9e5e5e5e5e5e9e9e9e5e5e5e5e5e5e5e5e5e5e5e5e5e5e",
	// }
	// for _, publicKey := range publicKeys {
	// 	pubKeyBytes, err := hex.DecodeString(publicKey)
	// 	if err != nil {
	// 		fmt.Println("无效的公钥：", err)
	// 		return
	// 	}
	// 	builder.AddData(pubKeyBytes)
	// }

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
	builder.AddOp(txscript.OP_2)
	for _, key := range allPubKeys {
		builder.AddData(key.ScriptAddress())
	}
	builder.AddOp(txscript.OP_3)
	builder.AddOp(txscript.OP_CHECKMULTISIG)
	// script, err := builder.Script()
	// if err != nil {
	// 	// Handle the error.
	// 	return
	// }
	// builder := txscript.NewScriptBuilder().AddInt64(int64(minSignNum))
	// for _, key := range allPubKeys {
	// 	builder.AddData(key.ScriptAddress())
	// }
	// builder.AddInt64(int64(len(allPubKeys)))
	// builder.AddOp(txscript.OP_CHECKMULTISIG)

	witnessScript, err := builder.Script()
	if err != nil {
		return "", nil, err
	}
	h256 := sha256.Sum256(witnessScript)
	witnessProg := h256[:]
	fmt.Println("len:", len(witnessProg))
	address, err := btcutil.NewAddressWitnessScriptHash(witnessProg, net)
	if err != nil {
		return "", nil, err
	}
	return address.EncodeAddress(), witnessScript, nil
}
