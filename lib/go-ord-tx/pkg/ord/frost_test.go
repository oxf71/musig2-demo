package ord_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/oxf71/musig2-demo/lib/go-ord-tx/pkg/ord"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/taproot"
)

func TestSign(t *testing.T) {
	group := curve.Secp256k1{}
	N := 3
	threshold := 2
	partyIds := ord.PartyIDs(N)

	secret := sample.Scalar(rand.Reader, group)

	publicPoint := secret.ActOnBase()
	if !publicPoint.(*curve.Secp256k1Point).HasEvenY() {
		secret.Negate()
	}

	f := polynomial.NewPolynomial(group, threshold, secret)

	publicKey := taproot.PublicKey(publicPoint.(*curve.Secp256k1Point).XBytes())

	fmt.Println(partyIds)
	t.Fail()
}
