package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/oxf71/musig2-demo/lib/go-ord-tx/pkg/btcapi/mempool"
	"github.com/oxf71/musig2-demo/lib/go-ord-tx/pkg/ord"
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
	netParams := &chaincfg.SigNetParams
	btcApiClient := mempool.NewClient(netParams)
	privKey1, _ := btcec.PrivKeyFromBytes(decodeHex("440bb3ec56d213e90d006d344d74f6478db4f7fa4cdd388095d8f4edef0c5156"))
	privKey2, _ := btcec.PrivKeyFromBytes(decodeHex("e0087817fd1d1154a781c11b394a0dcec82f076bbf026df9d61667ead16fa778"))

	musigPrivKey := musig2demo.TwoBtcTaprootAddress(privKey1, privKey2)

	musigPriv := make([]*btcec.PrivateKey, 0)
	musigPriv = append(musigPriv, privKey1, privKey2)

	musigAddress, _ := btcutil.DecodeAddress(musigPrivKey, netParams)

	utxoPrivateKeyHex := "440bb3ec56d213e90d006d344d74f6478db4f7fa4cdd388095d8f4edef0c5156"
	utxoPrivateKeyBytes, err := hex.DecodeString(utxoPrivateKeyHex)
	if err != nil {
		log.Fatal(err)
	}
	utxoPrivateKey, _ := btcec.PrivKeyFromBytes(utxoPrivateKeyBytes)

	utxoPublicKey := utxoPrivateKey.PubKey()

	utxoTaprootAddress, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(utxoPublicKey)), netParams)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("utxoTaprootAddress:", utxoTaprootAddress.EncodeAddress())
	fmt.Println("musigAddress no script:", musigAddress.EncodeAddress())

	unspentList, err := btcApiClient.ListUnspent(utxoTaprootAddress)

	if err != nil {
		log.Fatalf("list unspent err %v", err)
	}

	if len(unspentList) == 0 {
		log.Fatal("no unspent")
	}

	commitTxOutPointList := make([]*wire.OutPoint, 0)
	commitTxPrivateKeyList := make([]*btcec.PrivateKey, 0)
	for i := range unspentList {
		// if i > 0 {
		// 	break
		// }
		commitTxOutPointList = append(commitTxOutPointList, unspentList[i].Outpoint)
		commitTxPrivateKeyList = append(commitTxPrivateKeyList, utxoPrivateKey)
		fmt.Println("unspentList:", unspentList[i].Outpoint)
	}

	// panic("err")

	dataList := make([]ord.InscriptionData, 0)

	dataList = append(dataList, ord.InscriptionData{
		ContentType: "text/plain;charset=utf-8",
		Body:        []byte("Create Without full Node "),
		Destination: "tb1prggx0jcdqgag2kj9agxa7n6p888ffpzs4flps8ztwctrluz040hq6x9sz8",
	})

	request := ord.InscriptionRequest{
		CommitTxOutPointList:   commitTxOutPointList,
		CommitTxPrivateKeyList: commitTxPrivateKeyList,
		CommitFeeRate:          18,
		FeeRate:                19,
		DataList:               dataList,
		SingleRevealTxOnly:     false,
	}

	tool, err := ord.NewInscriptionToolWithBtcApiClient(netParams, btcApiClient, &request, musigPriv)
	if err != nil {
		log.Fatalf("Failed to create inscription tool: %v", err)
	}
	recoveryKeyWIFList := tool.GetRecoveryKeyWIFList()
	for i, recoveryKeyWIF := range recoveryKeyWIFList {
		log.Printf("recoveryKeyWIF %d %s \n", i, recoveryKeyWIF)
	}

	commitTxHex, err := tool.GetCommitTxHex()
	if err != nil {
		log.Fatalf("get commit tx hex err, %v", err)
	}
	log.Printf("commitTxHex %s \n", commitTxHex)
	revealTxHexList, err := tool.GetRevealTxHexList()
	if err != nil {
		log.Fatalf("get reveal tx hex err, %v", err)
	}
	for i, revealTxHex := range revealTxHexList {
		log.Printf("revealTxHex %d %s \n", i, revealTxHex)
	}
	commitTxHash, revealTxHashList, inscriptions, fees, err := tool.Inscribe()
	if err != nil {
		log.Fatalf("send tx errr, %v", err)
	}
	log.Println("commitTxHash, " + commitTxHash.String())
	for i := range revealTxHashList {
		log.Println("revealTxHash, " + revealTxHashList[i].String())
	}
	for i := range inscriptions {
		log.Println("inscription, " + inscriptions[i])
	}
	log.Println("fees: ", fees)
}
