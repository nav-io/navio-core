P2P and network changes
-----------------------

- Missing parents of an orphan transaction are now requested by output id with a
  `MSG_WITNESS_TX` getdata (#502), a form every released version answers with
  the transaction that created that output.

  No version released so far (v0.2.2 and older) applies the Dandelion++ stem
  embargo to such a request: it checks the embargo by txid, while the request
  names an output id, so the check never matches. A peer running one of these
  versions can therefore reply with a parent that is still in its stem phase as
  a plain `tx`, ending its stem phase early. This is not new (any peer could
  already send such a request), and it goes away as peers upgrade.
