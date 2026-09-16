// Copyright (c) 2015-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ZMQ_ZMQNOTIFICATIONINTERFACE_H
#define BITCOIN_ZMQ_ZMQNOTIFICATIONINTERFACE_H

#include <primitives/transaction.h>
#include <p2pmsg/user_inbox.h>
#include <validationinterface.h>

#include <cstdint>
#include <functional>
#include <list>
#include <memory>

class CBlock;
class CBlockIndex;
class CZMQAbstractNotifier;
struct NewMempoolTransactionInfo;

class CZMQNotificationInterface final : public CValidationInterface
{
public:
    ~CZMQNotificationInterface();

    std::list<const CZMQAbstractNotifier*> GetActiveNotifiers() const;

    //! Publish a stored p2pmsg user message. NOT a CValidationInterface hook:
    //! callers must invoke it on the validation-interface queue
    //! (CallFunctionInValidationInterfaceQueue) so it is serialized with the
    //! validation-driven notifications onto the same background thread.
    void NotifyP2PMsg(const p2pmsg::UserInbox::Entry& entry);

    static std::unique_ptr<CZMQNotificationInterface> Create(std::function<bool(CBlock&, const CBlockIndex&)> get_block_by_index);

protected:
    bool Initialize();
    void Shutdown();

    // CValidationInterface
    void TransactionAddedToMempool(const NewMempoolTransactionInfo& tx, uint64_t mempool_sequence) override;
    void TransactionRemovedFromMempool(const CTransactionRef& tx, MemPoolRemovalReason reason, uint64_t mempool_sequence) override;
    void BlockConnected(ChainstateRole role, const std::shared_ptr<const CBlock>& pblock, const CBlockIndex* pindexConnected) override;
    void BlockDisconnected(const std::shared_ptr<const CBlock>& pblock, const CBlockIndex* pindexDisconnected) override;
    void UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload) override;

private:
    CZMQNotificationInterface();

    void* pcontext{nullptr};
    std::list<std::unique_ptr<CZMQAbstractNotifier>> notifiers;
};

extern std::unique_ptr<CZMQNotificationInterface> g_zmq_notification_interface;

#endif // BITCOIN_ZMQ_ZMQNOTIFICATIONINTERFACE_H
