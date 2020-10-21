/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix_test

import (
	"testing"

	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/VoneChain-CS/fabric-ca-gm/lib/server/idemix"
	"github.com/VoneChain-CS/fabric-ca-gm/util"
	fabidemix "github.com/VoneChain-CS/fabric-gm/idemix"
)

func TestIdemixPanic(t *testing.T) {
	var err error

	rnd, err := fabidemix.GetRand()
	if err != nil {
		t.Fatalf("Error generating a random number")
	}
	nonce := FP256BN.NewBIGint(1)
	credReq, _, err := newIdemixCredentialRequest(t, nonce)
	if err != nil {
		t.Fatalf("Failed to create credential request: %s", err.Error())
	}

	libImpl := idemix.NewLib()
	_, err = libImpl.NewCredential(nil, credReq, nil, rnd)
	util.ErrorContains(t, err, "failure: runtime error", "NewCredential should have caught panic, and returned an error")

}
