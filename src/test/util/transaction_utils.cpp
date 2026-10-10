// Copyright (c) 2019-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <test/util/transaction_utils.h>

#include <algorithm>

CMutableTransaction BuildCreditingTransaction(const CScript& scriptPubKey, int nValue)
{
    CMutableTransaction txCredit;
    txCredit.version = 1;
    txCredit.nLockTime = 0;
    txCredit.vin.resize(1);
    txCredit.vout.resize(1);
    txCredit.vin[0].prevout.SetNull();
    txCredit.vin[0].scriptSig = CScript() << CScriptNum(0) << CScriptNum(0);
    txCredit.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    txCredit.vout[0].scriptPubKey = scriptPubKey;
    txCredit.vout[0].nValue = nValue;

    return txCredit;
}

CMutableTransaction BuildSpendingTransaction(const CScript& scriptSig, const CScriptWitness& scriptWitness, const CTransaction& txCredit)
{
    CMutableTransaction txSpend;
    txSpend.version = 1;
    txSpend.nLockTime = 0;
    txSpend.vin.resize(1);
    txSpend.vout.resize(1);
    txSpend.vin[0].scriptWitness = scriptWitness;
    txSpend.vin[0].prevout.hash = txCredit.GetHash();
    txSpend.vin[0].prevout.n = 0;
    txSpend.vin[0].scriptSig = scriptSig;
    txSpend.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    txSpend.vout[0].scriptPubKey = CScript();
    txSpend.vout[0].nValue = txCredit.vout[0].nValue;

    return txSpend;
}

std::vector<CMutableTransaction> SetupDummyInputs(FillableSigningProvider& keystoreRet, CCoinsViewCache& coinsRet, const std::array<CAmount,4>& nValues)
{
    std::vector<CMutableTransaction> dummyTransactions;
    dummyTransactions.resize(2);

    // Add some keys to the keystore:
    CKey key[4];
    for (int i = 0; i < 4; i++) {
        key[i].MakeNewKey(i % 2);
        keystoreRet.AddKey(key[i]);
    }

    // Create some dummy input transactions
    dummyTransactions[0].vout.resize(2);
    dummyTransactions[0].vout[0].nValue = nValues[0];
    dummyTransactions[0].vout[0].scriptPubKey << ToByteVector(key[0].GetPubKey()) << OP_CHECKSIG;
    dummyTransactions[0].vout[1].nValue = nValues[1];
    dummyTransactions[0].vout[1].scriptPubKey << ToByteVector(key[1].GetPubKey()) << OP_CHECKSIG;
    AddCoins(coinsRet, CTransaction(dummyTransactions[0]), 0);

    dummyTransactions[1].vout.resize(2);
    dummyTransactions[1].vout[0].nValue = nValues[2];
    dummyTransactions[1].vout[0].scriptPubKey = GetScriptForDestination(PKHash(key[2].GetPubKey()));
    dummyTransactions[1].vout[1].nValue = nValues[3];
    dummyTransactions[1].vout[1].scriptPubKey = GetScriptForDestination(PKHash(key[3].GetPubKey()));
    AddCoins(coinsRet, CTransaction(dummyTransactions[1]), 0);

    return dummyTransactions;
}

static CScript PaymentScript(size_t len)
{
    CScript script;
    script.reserve(len);
    for (size_t i{0}; i < len; ++i) {
        script << OP_TRUE;
    }
    return script;
}

void BulkTransaction(CMutableTransaction& tx, int32_t target_weight)
{
    // Payment outputs, each at most 34 bytes. The transaction is large
    // because it pays more outputs. A data script is not a size knob.
    auto weight = [&] { return static_cast<int32_t>(GetTransactionWeight(CTransaction(tx))); };
    assert(weight() <= target_weight);
    const size_t original_outputs{tx.vout.size()};
    const CScript full{PaymentScript(MAX_OUTPUT_SCRIPT_SIZE)};
    while (true) {
        tx.vout.emplace_back(0, full);
        if (weight() > target_weight) {
            tx.vout.pop_back();
            break;
        }
    }
    if (weight() == target_weight) return;

    for (size_t len{1}; len <= MAX_OUTPUT_SCRIPT_SIZE; ++len) {
        tx.vout.emplace_back(0, PaymentScript(len));
        if (weight() == target_weight) return;
        tx.vout.pop_back();
        if (weight() > target_weight) break;
    }

    assert(tx.vout.size() > original_outputs);
    CScript& pad{tx.vout.back().scriptPubKey};
    const CScript saved{pad};
    for (size_t cut{1}; cut < saved.size(); ++cut) {
        pad = CScript(saved.begin(), saved.begin() + saved.size() - cut);
        for (size_t len{1}; len <= MAX_OUTPUT_SCRIPT_SIZE; ++len) {
            tx.vout.emplace_back(0, PaymentScript(len));
            if (weight() == target_weight) return;
            tx.vout.pop_back();
        }
    }
    assert(weight() == target_weight);
}

bool SignSignature(const SigningProvider &provider, const CScript& fromPubKey, CMutableTransaction& txTo, unsigned int nIn, const CAmount& amount, int nHashType, SignatureData& sig_data)
{
    assert(nIn < txTo.vin.size());

    MutableTransactionSignatureCreator creator(txTo, nIn, amount, nHashType);

    bool ret = ProduceSignature(provider, creator, fromPubKey, sig_data);
    UpdateInput(txTo.vin.at(nIn), sig_data);
    return ret;
}

bool SignSignature(const SigningProvider &provider, const CTransaction& txFrom, CMutableTransaction& txTo, unsigned int nIn, int nHashType, SignatureData& sig_data)
{
    assert(nIn < txTo.vin.size());
    const CTxIn& txin = txTo.vin[nIn];
    assert(txin.prevout.n < txFrom.vout.size());
    const CTxOut& txout = txFrom.vout[txin.prevout.n];

    return SignSignature(provider, txout.scriptPubKey, txTo, nIn, txout.nValue, nHashType, sig_data);
}
