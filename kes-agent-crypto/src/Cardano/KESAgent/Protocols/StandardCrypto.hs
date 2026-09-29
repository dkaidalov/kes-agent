{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}

-- | Standard crypto implementations. These mirror the respective types in
-- @ouroboros-consensus@ / @cardano-ledger@; we are redefining them here to
-- avoid depending on those packages, and skip the parts that aren't relevant
-- to KES agents.
module Cardano.KESAgent.Protocols.StandardCrypto
where

import Cardano.KESAgent.KES.Crypto
import Cardano.KESAgent.Protocols.VersionedProtocol

import Cardano.Crypto.DSIGN.Ed25519
import Cardano.Crypto.DSIGN.MLDSA44 (MLDSA44DSIGN)
import Cardano.Crypto.Hash.Blake2b
import Cardano.Crypto.KES.CompactSum
import Cardano.Crypto.KES.HashedSingle (HashedCompactSum6KES)
import Cardano.Crypto.KES.Mock
import Cardano.Crypto.KES.Padded (PaddedKES)
import Cardano.Crypto.KES.Single
import Cardano.Crypto.KES.Sum

-- | The standard crypto used on the production chain.
data StandardCrypto

-- | A variant of 'StandardCrypto' that uses the @Compact@ flavors of the KES
-- types ('CompactSumKES' and 'CompactSingleKES').
data CompactStandardCrypto

-- | Crypto that uses 'SingleKES'. Only used for testing.
data SingleCrypto

-- | Mock crypto. Only used for testing.
data MockCrypto

-- Experimental KES selection for the post-quantum header experiments. The
-- same CPP defines as cardano-ledger's Cardano.Protocol.Crypto select the
-- scheme, and the two packages must be built with the same defines:
--
-- > package kes-agent-crypto
-- >   cpp-options: -DPQ_KES_MLDSA44 -DPQ_KES_PAD=3636 -DPQ_KES_SPIN=0
--
-- With no defines the scheme is mainnet's Sum6KES Ed25519DSIGN Blake2b_256
-- wrapped in PaddedKES 0 0, which changes nothing but the algorithm name.
#ifndef PQ_KES_PAD
#define PQ_KES_PAD 0
#endif
#ifndef PQ_KES_SPIN
#define PQ_KES_SPIN 0
#endif

#if defined(PQ_KES_MLDSA44)
type StandardKESInner = HashedCompactSum6KES MLDSA44DSIGN Blake2b_256
#else
type StandardKESInner = Sum6KES Ed25519DSIGN Blake2b_256
#endif

instance Crypto StandardCrypto where
  type KES StandardCrypto = PaddedKES PQ_KES_PAD PQ_KES_SPIN StandardKESInner
  type DSIGN StandardCrypto = Ed25519DSIGN

instance Crypto CompactStandardCrypto where
  type KES CompactStandardCrypto = CompactSum6KES Ed25519DSIGN Blake2b_256
  type DSIGN CompactStandardCrypto = Ed25519DSIGN

instance Crypto SingleCrypto where
  type KES SingleCrypto = SingleKES Ed25519DSIGN
  type DSIGN SingleCrypto = Ed25519DSIGN

instance Crypto MockCrypto where
  type KES MockCrypto = MockKES 128
  type DSIGN MockCrypto = Ed25519DSIGN

instance NamedCrypto StandardCrypto where
  cryptoName _ = CryptoName "StandardCrypto"

instance NamedCrypto CompactStandardCrypto where
  cryptoName _ = CryptoName "CompactStandardCrypto"

instance NamedCrypto SingleCrypto where
  cryptoName _ = CryptoName "SingleCrypto"

instance NamedCrypto MockCrypto where
  cryptoName _ = CryptoName "MockCrypto"
