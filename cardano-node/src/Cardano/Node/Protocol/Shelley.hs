{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module Cardano.Node.Protocol.Shelley
  ( mkSomeConsensusProtocolShelley

    -- * Errors
  , ShelleyProtocolInstantiationError(..)
  , GenesisReadError(..)
  , GenesisValidationError(..)
  , PraosLeaderCredentialsError(..)

    -- * Reusable parts
  , readGenesis
  , readGenesisAny
  , readLeaderCredentials
  , readLeaderCredentialsForGenesis
  , validateCredentialIdentities
  , genesisHashToPraosNonce
  , validateGenesis
  , checkExpectedGenesisHash
  ) where

import           Cardano.Api hiding (FileError)
import qualified Cardano.Api as Api
import           Cardano.Api.Experimental.Certificate (OperationalCertificate (..), getHotKey)

import qualified Cardano.Crypto.Hash as Crypto
import           Cardano.Ledger.BaseTypes (ProtVer (..), natVersion)
import           Cardano.Ledger.Keys (coerceKeyRole)
import qualified Cardano.Ledger.Shelley.Genesis as Shelley
import           Cardano.Node.Orphans ()
import Cardano.Node.Protocol.Shelley.Credentials
import Cardano.Node.Protocol.Shelley.KesForge
import           Cardano.Node.Protocol.Types
import           Cardano.Node.Tracing.Era.HardFork ()
import           Cardano.Node.Tracing.Era.Shelley ()
import           Cardano.Node.Tracing.Formatting ()
import           Cardano.Node.Tracing.Tracers.ChainDB ()
import           Cardano.Node.Types
import qualified Ouroboros.Consensus.Cardano as Consensus
import qualified Ouroboros.Consensus.Protocol.KesForge.Client as KesForge
import           Ouroboros.Consensus.HardFork.Combinator.AcrossEras ()
import           Ouroboros.Consensus.Protocol.Praos.Common (PraosCanBeLeader (..),
                   PraosCredentialsSource (..))
import           Ouroboros.Consensus.Shelley.Node (Nonce (..), ProtocolParamsShelleyBased (..),
                   ShelleyLeaderCredentials (..))

import           Control.Exception (IOException)
import           Control.Monad
import qualified Data.Aeson as Aeson
import qualified Data.ByteString as BS
import qualified Data.Set as Set
import qualified Data.Text as T
import           System.Directory (getFileSize)
import System.FilePath (isAbsolute, normalise, takeDirectory, (</>))
import           System.FS.API (SomeHasFS (..))
import           System.FS.API.Types (MountPoint (MountPoint))
import           System.FS.IO (ioHasFS)
import qualified System.IO.MMap as MMap


------------------------------------------------------------------------------
-- Shelley protocol
--

-- | Make 'SomeConsensusProtocol' using the Shelley instance.
--
-- This lets us handle multiple protocols in a generic way.
--
-- This also serves a purpose as a sanity check that we have all the necessary
-- type class instances available.
mkSomeConsensusProtocolShelley
  :: NodeShelleyProtocolConfiguration
  -> Maybe ProtocolFilepaths
  -> ExceptT ShelleyProtocolInstantiationError IO SomeConsensusProtocol
mkSomeConsensusProtocolShelley NodeShelleyProtocolConfiguration {
                                  npcShelleyGenesisFile,
                                  npcShelleyGenesisFileHash
                                }
                          files = do
    (genesis, genesisHash) <- firstExceptT GenesisReadError $
                              readGenesis npcShelleyGenesisFile
                                          npcShelleyGenesisFileHash
    firstExceptT GenesisValidationError $ validateGenesis genesis
    leaderCredentials <- firstExceptT PraosLeaderCredentialsError $
                         readLeaderCredentialsForGenesis genesis genesisHash files

    -- Filesystem rooted at the Shelley genesis directory, used by the ledger to
    -- read initial funds/staking injected from genesis (testnets only).
    let shelleyGenesisFS = SomeHasFS $ ioHasFS $ MountPoint $ takeDirectory $ unGenesisFile npcShelleyGenesisFile

    return $ SomeConsensusProtocol Api.ShelleyBlockType $ Api.ProtocolInfoArgsShelley
      shelleyGenesisFS
      genesis
      Consensus.ProtocolParamsShelleyBased {
        shelleyBasedInitialNonce = genesisHashToPraosNonce genesisHash,
        shelleyBasedLeaderCredentials =
            leaderCredentials
      }
      (ProtVer (natVersion @2) 0)


genesisHashToPraosNonce :: GenesisHash -> Nonce
genesisHashToPraosNonce (GenesisHash h) = Nonce (Crypto.castHash h)

readGenesis :: GenesisFile
            -> Maybe GenesisHash
            -> ExceptT GenesisReadError IO
                       (ShelleyGenesis, GenesisHash)
readGenesis = readGenesisAny

-- | Read a genesis file using a memory-safe strategy.
--
-- Genesis files are used in testing and benchmarking to create testnets with
-- large datasets. To be able to read these files in memory constrained
-- environments we use a conditional loading strategy: if file is below ~10
-- megabytes it is entirely read into memory, otherwise the 'ByteString' is
-- created using `mmap` that uses the virtual memory subsystem to do on-demand
-- loading.
-- With current usage and how benchmakring is done only Shelley and Conway are
-- affected (Shelley's `initialFunds` and Conway's "delegs" and "initialDReps").
readGenesisAny :: FromJSON genesis
               => GenesisFile
               -> Maybe GenesisHash
               -> ExceptT GenesisReadError IO (genesis, GenesisHash)
readGenesisAny (GenesisFile file) mExpectedGenesisHash = do
    content <- handleIOExceptT (GenesisReadFileError file) $ do
        -- Size of the file in 8-bit bytes.
        size <- getFileSize file
        {-- Mainnet files for reference:
              -byron-genesis.json:   1056360 (1.1M)
              -shelley-genesis.json:    2486 (2.5K)
              -alonzo-genesis.json:     9459 (9.3K)
              -conway-genesis.json:     4168 (4.1K)
        --}
        if size >= 10485760 -- 10 megabytes.
        then MMap.mmapFileByteString file Nothing -- MMap version.
        else BS.readFile file                     -- Non-lazy version.
    genesisHash <- checkExpectedGenesisHash content mExpectedGenesisHash
    genesis <- firstExceptT (GenesisDecodeError file) $ hoistEither $
                 Aeson.eitherDecodeStrict' content
    return (genesis, genesisHash)

checkExpectedGenesisHash
  :: BS.ByteString -- ^ genesis bytes
  -> Maybe GenesisHash -- ^ expected hash, check for hash match, if provided
  -> ExceptT GenesisReadError IO GenesisHash
checkExpectedGenesisHash genesisBytes mExpected = do
  let actual = GenesisHash $ Crypto.hashWith id genesisBytes
  forM_ mExpected $ \expected ->
    when (actual /= expected) $
      throwError (GenesisHashMismatch actual expected)
  pure actual

validateGenesis :: ShelleyGenesis
                -> ExceptT GenesisValidationError IO ()
validateGenesis genesis =
    firstExceptT GenesisValidationErrors . hoistEither $
      Shelley.validateGenesis genesis

data LoadedCredential = LoadedCredential
  { loadedPoolId :: !BS.ByteString
  , loadedIsDeviceBacked :: !Bool
  , loadedCredential :: !(ShelleyLeaderCredentials StandardCrypto)
  }

readLeaderCredentials
  :: Maybe ProtocolFilepaths
  -> ExceptT PraosLeaderCredentialsError IO [ShelleyLeaderCredentials StandardCrypto]
readLeaderCredentials = readLeaderCredentialsWithBinding Nothing

readLeaderCredentialsForGenesis
  :: ShelleyGenesis
  -> GenesisHash
  -> Maybe ProtocolFilepaths
  -> ExceptT PraosLeaderCredentialsError IO [ShelleyLeaderCredentials StandardCrypto]
readLeaderCredentialsForGenesis genesis genesisHash =
  readLeaderCredentialsWithBinding $ Just $ expectedNetworkBinding genesis genesisHash

readLeaderCredentialsWithBinding
  :: Maybe KesForge.NetworkBinding
  -> Maybe ProtocolFilepaths
  -> ExceptT PraosLeaderCredentialsError IO [ShelleyLeaderCredentials StandardCrypto]
readLeaderCredentialsWithBinding _ Nothing = return []
readLeaderCredentialsWithBinding expectedBinding (Just pfp) = do
  loaded <-
    (<>)
      <$> readLeaderCredentialsSingleton expectedBinding pfp
      <*> readLeaderCredentialsBulk expectedBinding pfp
  hoistEither $
    validateCredentialIdentities $
      fmap (\credential -> (loadedPoolId credential, loadedIsDeviceBacked credential)) loaded
  pure $ fmap loadedCredential loaded

validateCredentialIdentities
  :: [(BS.ByteString, Bool)]
  -> Either PraosLeaderCredentialsError ()
validateCredentialIdentities credentials = do
  let poolIds = fmap fst credentials
      deviceBackedCount = length $ filter snd credentials
  when (Set.size (Set.fromList poolIds) /= length poolIds) $
    Left DuplicatePoolIdentity
  when (deviceBackedCount > 32) $
    Left TooManyDeviceCredentials

expectedNetworkBinding :: ShelleyGenesis -> GenesisHash -> KesForge.NetworkBinding
expectedNetworkBinding genesis (GenesisHash genesisHash) =
  KesForge.NetworkBinding
    { KesForge.networkMagic = fromIntegral $ Shelley.sgNetworkMagic genesis
    , KesForge.shelleyGenesisDigest = Crypto.hashToBytes genesisHash
    , KesForge.slotsPerKESPeriod = Shelley.sgSlotsPerKESPeriod genesis
    , KesForge.maxKESEvolutions = Shelley.sgMaxKESEvolutions genesis
    }

readLeaderCredentialsSingleton
  :: Maybe KesForge.NetworkBinding
  -> ProtocolFilepaths
  -> ExceptT PraosLeaderCredentialsError IO [LoadedCredential]
readLeaderCredentialsSingleton
  _
  ProtocolFilepaths
    { shelleyCertFile = Nothing
    , shelleyVRFFile = Nothing
    , shelleyKESSource = Nothing
    } = pure []
readLeaderCredentialsSingleton
  expectedBinding
  ProtocolFilepaths
    { shelleyCertFile = Just opCertFile
    , shelleyVRFFile = Just vrfFile
    , shelleyKESSource = Just kesSource
    } = do
      vrfSKey <-
        firstExceptT FileError (newExceptT $ readFileTextEnvelope (File vrfFile))
      (credentialsSource, vkey, deviceBacked) <- case kesSource of
        KESKeyFilePath kesFile -> do
          (OperationalCertificate opCert vkey, KesSigningKey kesKey) <-
            opCertKesKeyCheck (File kesFile) (File opCertFile)
          pure (PraosCredentialsUnsound opCert kesKey, vkey, False)
        KESAgentSocketPath socketFile -> do
          OperationalCertificate _ vkey <-
            firstExceptT FileError $ newExceptT $ readFileTextEnvelope $ File opCertFile
          pure (PraosCredentialsAgent socketFile, vkey, False)
        KESForgeConfigPath configFile -> do
          opCertEnvelope <- readEnvelopeFile opCertFile
          OperationalCertificate opCert vkey <-
            parseEnvelope (opCertEnvelope, opCertFile)
          config <- loadKesForgeConfig configFile
          validateForgePool expectedBinding configFile vkey config
          pure
            ( PraosCredentialsExternal opCert (certificateDigest opCertEnvelope) $ kesForgeConnection config
            , vkey
            , True
            )
      pure
        [ LoadedCredential
            { loadedPoolId = poolIdentity vkey
            , loadedIsDeviceBacked = deviceBacked
            , loadedCredential = mkPraosLeaderCredentials credentialsSource vkey vrfSKey
            }
        ]
readLeaderCredentialsSingleton _ ProtocolFilepaths {shelleyCertFile = Nothing} =
  left OCertNotSpecified
readLeaderCredentialsSingleton _ ProtocolFilepaths {shelleyVRFFile = Nothing} =
  left VRFKeyNotSpecified
readLeaderCredentialsSingleton _ ProtocolFilepaths {shelleyKESSource = Nothing} =
  left KESKeyNotSpecified

opCertKesKeyCheck
  :: File () In
  -- ^ KES key
  -> File () In
  -- ^ Operational certificate
  -> ExceptT PraosLeaderCredentialsError IO (OperationalCertificate, SigningKey KesKey)
opCertKesKeyCheck kesFile certFile = do
  opCert <-
    firstExceptT FileError (newExceptT $ readFileTextEnvelope certFile)
  kesSKey <-
    firstExceptT FileError (newExceptT $ readFileTextEnvelope kesFile)
  hoistEither $ validateKesKeyBinding (unFile kesFile) (unFile certFile) opCert kesSKey
  return (opCert, kesSKey)

-- | Apply the same certificate/key binding policy to singleton and bulk keys.
-- Locations are filenames for singleton input and indexed fields for bulk input.
validateKesKeyBinding
  :: FilePath
  -> FilePath
  -> OperationalCertificate
  -> SigningKey KesKey
  -> Either PraosLeaderCredentialsError ()
validateKesKeyBinding kesLocation certLocation opCert kesSKey =
  if verificationKeyHash (getVerificationKey kesSKey) == verificationKeyHash (getHotKey opCert)
    then Right ()
    else Left $ MismatchedKesKey kesLocation certLocation

readLeaderCredentialsBulk
  :: Maybe KesForge.NetworkBinding
  -> ProtocolFilepaths
  -> ExceptT PraosLeaderCredentialsError IO [LoadedCredential]
readLeaderCredentialsBulk _ ProtocolFilepaths{shelleyBulkCredsFile = Nothing} = pure []
readLeaderCredentialsBulk expectedBinding ProtocolFilepaths{shelleyBulkCredsFile = Just file} = do
  content <- handleIOExceptT (CredentialsReadError file) $ BS.readFile file
  credentials <- firstExceptT (EnvelopeParseError file) $ hoistEither $
    decodeBulkCredentials file content
  mapM (uncurry $ parseCredential file) $ zip [0 :: Int ..] credentials
 where
  parseCredential bulkFile index BulkCredential
    { bulkOperationalCertificate
    , bulkVrfSigningKey
    , bulkKESSource
    } = do
      let location fieldName = bulkFile <> "[" <> show index <> "]." <> fieldName
      operationalCertificate@(OperationalCertificate opCert vkey) <-
        parseEnvelope (bulkOperationalCertificate, location "operationalCertificate")
      vrfSKey <- parseEnvelope (bulkVrfSigningKey, location "vrfSigningKey")
      (source, deviceBacked) <- case bulkKESSource of
        BulkKESFile envelope -> do
          kesSKey@(KesSigningKey kesKey) <- parseEnvelope (envelope, location "kesSource.signingKey")
          hoistEither $
            validateKesKeyBinding
              (location "kesSource.signingKey")
              (location "operationalCertificate")
              operationalCertificate
              kesSKey
          pure (PraosCredentialsUnsound opCert kesKey, False)
        BulkKESForge relativeConfigFile -> do
          let configFile = resolveRelative bulkFile relativeConfigFile
          config <- loadKesForgeConfig configFile
          validateForgePool expectedBinding configFile vkey config
          pure
            ( PraosCredentialsExternal opCert (certificateDigest bulkOperationalCertificate) $ kesForgeConnection config
            , True
            )
      pure LoadedCredential
        { loadedPoolId = poolIdentity vkey
        , loadedIsDeviceBacked = deviceBacked
        , loadedCredential = mkPraosLeaderCredentials source vkey vrfSKey
        }

readEnvelopeFile
  :: FilePath
  -> ExceptT PraosLeaderCredentialsError IO TextEnvelope
readEnvelopeFile file = do
  content <- handleIOExceptT (CredentialsReadError file) $ BS.readFile file
  firstExceptT (EnvelopeParseError file) $ hoistEither $
    Aeson.eitherDecodeStrict' content

certificateDigest :: TextEnvelope -> BS.ByteString
certificateDigest =
  Crypto.hashToBytes
    . (Crypto.hashWith id :: BS.ByteString -> Crypto.Hash Crypto.SHA256 BS.ByteString)
    . teRawCBOR

loadKesForgeConfig
  :: FilePath
  -> ExceptT PraosLeaderCredentialsError IO KesForgePoolConfig
loadKesForgeConfig file = do
  content <- handleIOExceptT (CredentialsReadError file) $ BS.readFile file
  firstExceptT (KesForgeConfigParseError file) $ hoistEither $
    decodeKesForgePoolConfig file content

validateForgePool
  :: Maybe KesForge.NetworkBinding
  -> FilePath
  -> VerificationKey StakePoolKey
  -> KesForgePoolConfig
  -> ExceptT PraosLeaderCredentialsError IO ()
validateForgePool expectedBinding file vkey config = do
  unless (kesForgePoolId config == poolIdentity vkey) $
    left $ KesForgePoolMismatch file
  forM_ expectedBinding $ \expected ->
    case networkBindingMismatch expected $ KesForge.networkBinding $ kesForgeConnection config of
      Nothing -> pure ()
      Just field -> left $ KesForgeNetworkMismatch file field

networkBindingMismatch
  :: KesForge.NetworkBinding
  -> KesForge.NetworkBinding
  -> Maybe String
networkBindingMismatch expected actual
  | KesForge.networkMagic actual /= KesForge.networkMagic expected = Just "networkMagic"
  | KesForge.shelleyGenesisDigest actual /= KesForge.shelleyGenesisDigest expected = Just "shelleyGenesisDigest"
  | KesForge.slotsPerKESPeriod actual /= KesForge.slotsPerKESPeriod expected = Just "slotsPerKesPeriod"
  | KesForge.maxKESEvolutions actual /= KesForge.maxKESEvolutions expected = Just "maxKesEvolutions"
  | otherwise = Nothing

poolIdentity :: VerificationKey StakePoolKey -> BS.ByteString
poolIdentity = serialiseToRawBytes . verificationKeyHash

resolveRelative :: FilePath -> FilePath -> FilePath
resolveRelative containing path
  | isAbsolute path = normalise path
  | otherwise = normalise $ takeDirectory containing </> path

mkPraosLeaderCredentials ::
     PraosCredentialsSource StandardCrypto
  -> VerificationKey StakePoolKey
  -> SigningKey VrfKey
  -> ShelleyLeaderCredentials StandardCrypto
mkPraosLeaderCredentials
    credentialsSource
    (StakePoolVerificationKey vkey)
    (VrfSigningKey vrfKey) =
    ShelleyLeaderCredentials
    { shelleyLeaderCredentialsCanBeLeader =
        PraosCanBeLeader {
          praosCanBeLeaderCredentialsSource = credentialsSource,
          praosCanBeLeaderColdVerKey = coerceKeyRole vkey,
          praosCanBeLeaderSignKeyVRF = vrfKey
        },
      shelleyLeaderCredentialsLabel = "Shelley"
    }

parseEnvelope ::
     HasTextEnvelope a
  => (TextEnvelope, String)
  -> ExceptT PraosLeaderCredentialsError IO a
parseEnvelope (te, loc) =
  firstExceptT (FileError . Api.FileError loc) . hoistEither $
    deserialiseFromTextEnvelope te


------------------------------------------------------------------------------
-- Errors
--

data ShelleyProtocolInstantiationError =
       GenesisReadError GenesisReadError
     | GenesisValidationError GenesisValidationError
     | PraosLeaderCredentialsError PraosLeaderCredentialsError
  deriving Show

instance Error ShelleyProtocolInstantiationError where
  prettyError (GenesisReadError err) = prettyError err
  prettyError (GenesisValidationError err) = prettyError err
  prettyError (PraosLeaderCredentialsError err) = prettyError err


data GenesisReadError =
       GenesisReadFileError !FilePath !IOException
     | GenesisHashMismatch !GenesisHash !GenesisHash -- actual, expected
     | GenesisDecodeError !FilePath !String
  deriving Show

instance Error GenesisReadError where
  prettyError (GenesisReadFileError fp err) =
        "There was an error reading the genesis file: "
     <> pshow fp <> " Error: " <> pshow err

  prettyError (GenesisHashMismatch actual expected) =
        "Wrong genesis file: the actual hash is " <> pshow actual
     <> ", but the expected genesis hash given in the node "
     <> "configuration file is " <> pshow expected

  prettyError (GenesisDecodeError fp err) =
        "There was an error parsing the genesis file: "
     <> pshow fp <> " Error: " <> pshow err

newtype GenesisValidationError = GenesisValidationErrors [Shelley.ValidationErr]
  deriving Show

instance Error GenesisValidationError where
  prettyError (GenesisValidationErrors vErrs) =
    pshow (T.unlines (map Shelley.describeValidationErr vErrs))


data PraosLeaderCredentialsError =
       CredentialsReadError !FilePath !IOException
     | EnvelopeParseError !FilePath !String
     | FileError !(Api.FileError TextEnvelopeError)
     | KesForgeConfigParseError !FilePath !String
     | KesForgePoolMismatch !FilePath
     | KesForgeNetworkMismatch !FilePath !String
     | DuplicatePoolIdentity
     | TooManyDeviceCredentials
--TODO: pick a less generic constructor than FileError

     | OCertNotSpecified
     | VRFKeyNotSpecified
     | KESKeyNotSpecified
     | MismatchedKesKey
         FilePath
         -- KES signing key
         FilePath
         -- Operational certificate
  deriving Show

instance Error PraosLeaderCredentialsError where
  prettyError (CredentialsReadError fp err) =
        "There was an error reading a credentials file: "
     <> pshow fp <> " Error: " <> pshow err

  prettyError (EnvelopeParseError fp err) =
        "There was an error parsing a credentials envelope: "
     <> pshow fp <> " Error: " <> pshow err

  prettyError (KesForgeConfigParseError fp err) =
        "There was an error parsing a cardano-kes-forge connection file: "
     <> pshow fp <> " Error: " <> pshow err
  prettyError (KesForgePoolMismatch fp) =
    "The pool identity in the cardano-kes-forge connection file does not match the operational certificate: "
      <> pshow fp
  prettyError (KesForgeNetworkMismatch fp field) =
    "The " <> pshow field
      <> " network binding in the cardano-kes-forge connection file does not match the Shelley genesis: "
      <> pshow fp
  prettyError DuplicatePoolIdentity =
    "The configured forging credentials contain a duplicate stake pool identity"
  prettyError TooManyDeviceCredentials =
    "At most 32 cardano-kes-forge pool credentials may be configured"
  prettyError (FileError fileErr) = prettyError fileErr
  prettyError (MismatchedKesKey kesFp certFp) =
       "The KES key provided at: " <> pshow kesFp
    <> " does not match the KES key specified in the operational certificate at: " <> pshow certFp
  prettyError OCertNotSpecified  = pshow $ missingFlagMessage "shelley-operational-certificate"
  prettyError VRFKeyNotSpecified = pshow $ missingFlagMessage "shelley-vrf-key"
  prettyError KESKeyNotSpecified = pshow $ missingFlagMessage "shelley-kes-key"

missingFlagMessage :: String -> String
missingFlagMessage flag =
  "To create blocks, the --" <> flag <> " must also be specified"
