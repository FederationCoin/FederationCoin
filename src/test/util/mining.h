// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_MINING_H
#define BITCOIN_TEST_UTIL_MINING_H

#include <node/miner.h>
#include <script/script.h>

#include <memory>
#include <string>
#include <vector>

class CBlock;
class CChainParams;
class COutPoint;
class CScript;
namespace node {
struct NodeContext;
} // namespace node

/** Create a blockchain, starting from genesis */
std::vector<std::shared_ptr<CBlock>> CreateBlockChain(size_t total_height, const CChainParams& params);

/** Dilithium 44 coinbase script. P2WSH and bare scripts are consensus-rejected.
 *  `tag` selects a distinct program so a template can differ from mined outputs
 *  (BIP30). */
CScript FuzzPayableCoinbaseScript(uint8_t tag = 1);

/** Returns the generated coin */
COutPoint MineBlock(const node::NodeContext&,
                    const node::BlockAssembler::Options& assembler_options);

/**
 * Returns the generated coin (or Null if the block was invalid).
 * It is recommended to call RegenerateCommitments before mining the block to avoid merkle tree mismatches.
 **/
COutPoint MineBlock(const node::NodeContext&, std::shared_ptr<CBlock>& block);

/** Prepare a block to be mined */
std::shared_ptr<CBlock> PrepareBlock(const node::NodeContext&);
std::shared_ptr<CBlock> PrepareBlock(const node::NodeContext& node,
                                     const node::BlockAssembler::Options& assembler_options);

/** RPC-like helper function, returns the generated coin */
COutPoint generatetoaddress(const node::NodeContext&, const std::string& address);

#endif // BITCOIN_TEST_UTIL_MINING_H
