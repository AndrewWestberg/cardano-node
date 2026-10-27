{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

module Test.Cardano.Node.KesForgeTelemetry
  ( tests
  ) where

import Cardano.Logging
  ( Metric (IntM)
  , MetaTrace (severityFor)
  , Namespace (Namespace)
  , SeverityS (Alert, Info, Warning)
  , LogFormatting (asMetrics)
  )
import Cardano.Protocol.TPraos.OCert (KESPeriod (KESPeriod))
import Cardano.Slotting.Slot (SlotNo (SlotNo))
import qualified Data.ByteString as BS
import Hedgehog (Property, discover)
import qualified Hedgehog
import Ouroboros.Consensus.Protocol.Ledger.HotKey (KESEvolutionError (KESExternalEvolutionError), KESInfo (..))
import Ouroboros.Consensus.Protocol.KesForge.Client
import qualified Ouroboros.Consensus.Protocol.KesForge.Rotation as Rotation
import Ouroboros.Consensus.Node.Tracers (TraceForgeEvent (TraceForgeStateUpdateError))
import Ouroboros.Consensus.Shelley.HFEras (StandardBabbageBlock)
import Ouroboros.Consensus.Util.IOLike (Time, addTime, getMonotonicTime)

import Cardano.Node.Tracing.Tracers.ChainDB ()
import Cardano.Node.Tracing.Tracers.Consensus ()
import Cardano.Node.Tracing.Tracers.KESInfo ()

prop_confirmed_evolution_preserves_existing_metric_meaning :: Property
prop_confirmed_evolution_preserves_existing_metric_meaning = Hedgehog.property $ do
  asMetrics (kesInfo 9)
    Hedgehog.=== [ IntM "operationalCertificateStartKESPeriod" 100
                 , IntM "operationalCertificateExpiryKESPeriod" 164
                 , IntM "currentKESPeriod" 109
                 , IntM "remainingKESPeriods" 55
                 ]
  asMetrics (kesInfo 63)
    Hedgehog.=== [ IntM "operationalCertificateStartKESPeriod" 100
                 , IntM "operationalCertificateExpiryKESPeriod" 164
                 , IntM "currentKESPeriod" 163
                 , IntM "remainingKESPeriods" 1
                 ]

prop_existing_severity_thresholds_are_source_independent :: Property
prop_existing_severity_thresholds_are_source_independent = Hedgehog.property $ do
  let namespace = Namespace [] ["StateInfo"]
  severityFor namespace (Just $ kesInfo 56) Hedgehog.=== Just Info
  severityFor namespace (Just $ kesInfo 57) Hedgehog.=== Just Warning
  severityFor namespace (Just $ kesInfo 62) Hedgehog.=== Just Warning
  severityFor namespace (Just $ kesInfo 63) Hedgehog.=== Just Alert
  severityFor namespace (Just $ kesInfo 64) Hedgehog.=== Just Alert

prop_external_outage_uses_existing_error_sentinels :: Property
prop_external_outage_uses_existing_error_sentinels = Hedgehog.property $
  asMetrics
    ( TraceForgeStateUpdateError
        (SlotNo 777)
        (KESExternalEvolutionError (kesInfo 9) (KESPeriod 109)) ::
        TraceForgeEvent StandardBabbageBlock
    )
    Hedgehog.===
      [ IntM "Forge.StateUpdateError" 777
      , IntM "operationalCertificateStartKESPeriod" 100
      , IntM "operationalCertificateExpiryKESPeriod" 164
      , IntM "currentKESPeriod" 0
      , IntM "remainingKESPeriods" 0
      ]

prop_native_observations_use_monotonic_freshness_and_context :: Property
prop_native_observations_use_monotonic_freshness_and_context = Hedgehog.property $ do
  now <- Hedgehog.evalIO getMonotonicTime
  confirmed <- Hedgehog.evalEither $
    Rotation.adoptConfirmedDescriptor
      now
      connection
      descriptor
      Rotation.emptyObservationCache
  observations <- Hedgehog.evalEither $
    Rotation.recordNodePeriod
      now
      (Rotation.contextForDescriptor connection descriptor)
      109
      confirmed
  Rotation.observationState (plusMilliseconds 29999 now) observations
    Hedgehog.=== Rotation.ObservationFresh
  Rotation.observationState (plusMilliseconds 30000 now) observations
    Hedgehog.=== Rotation.ObservationStale
  Rotation.observationState (plusMilliseconds 30001 now) observations
    Hedgehog.=== Rotation.ObservationStale
  Rotation.observationState (plusMilliseconds (-1) now) observations
    Hedgehog.=== Rotation.ObservationStale
  Rotation.observationState now (Rotation.invalidateObservations observations)
    Hedgehog.=== Rotation.ObservationUnavailable
  Hedgehog.assert $ isLeft $
    Rotation.recordNodePeriod
      now
      (Rotation.contextForDescriptor connection descriptor)
        { Rotation.rotationGeneration = BS.replicate 16 99
        }
      109
      confirmed
  Hedgehog.assert $ isLeft $
    Rotation.adoptConfirmedDescriptor
      now
      connection
      descriptor
        { descriptorGeneration = BS.replicate 16 99
        , descriptorRevision = descriptorRevision descriptor - 1
        }
      observations

connection :: Connection
connection =
  Connection
    { socketPath = "/run/cardano-kes-forge/device.sock"
    , connectionName = "pool-0"
    , networkBinding =
        NetworkBinding
          { networkMagic = 42
          , shelleyGenesisDigest = BS.replicate 32 4
          , slotsPerKESPeriod = 64
          , maxKESEvolutions = 64
          }
    , deviceIdentity = BS.replicate 16 2
    , poolIdentity = BS.replicate 28 1
    , incarnationIdentity = BS.replicate 16 3
    , securityPolicy = PermitDevelopment
    }

descriptor :: PoolDescriptor
descriptor =
  PoolDescriptor
    { descriptorGeneration = BS.replicate 16 5
    , descriptorCertificateDigest = BS.replicate 32 6
    , descriptorCertificateStart = 100
    , descriptorCertificateCounter = 3
    , descriptorVerificationKey = BS.replicate 32 7
    , descriptorRevision = 8
    , descriptorRelativePeriod = 9
    }

plusMilliseconds :: Integer -> Time -> Time
plusMilliseconds milliseconds =
  addTime (fromRational $ toRational milliseconds / 1000)

isLeft :: Either a b -> Bool
isLeft Left{} = True
isLeft Right{} = False

kesInfo :: Word -> KESInfo
kesInfo evolution =
  KESInfo
    { kesStartPeriod = KESPeriod 100
    , kesEndPeriod = KESPeriod 164
    , kesEvolution = fromIntegral evolution
    }

tests :: IO Bool
tests = Hedgehog.checkParallel $$discover
