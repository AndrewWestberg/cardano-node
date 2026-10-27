{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

module Test.Cardano.Node.KesForgeCredentials
  ( tests
  ) where
import Cardano.Node.Configuration.POM (PartialNodeConfiguration (pncProtocolFiles))
import Cardano.Node.Parsers (nodeCLIParser)
import Cardano.Node.Types (KESSource (..), ProtocolFilepaths (..))

import Cardano.Node.Protocol.Shelley.Credentials
import Cardano.Node.Protocol.Shelley.KesForge
import Cardano.Node.Protocol.Shelley (PraosLeaderCredentialsError (..), readLeaderCredentials, validateCredentialIdentities)
import qualified Cardano.Api as Api
import qualified Cardano.Api.Experimental.Certificate as Certificate
import Control.Exception (bracket)
import Control.Monad (forM_)
import Control.Monad.Except (runExceptT)
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Lazy as LBS
import System.Directory (getTemporaryDirectory, removeFile)
import System.IO (hClose, openBinaryTempFile)
import Ouroboros.Consensus.Protocol.KesForge.Client

import Data.Monoid (getLast)
import Data.List (isInfixOf)
import Options.Applicative (ParserResult (Failure, Success), defaultPrefs, execParserPure, info)
import qualified Data.ByteString.Char8 as BS8
import Hedgehog (Property, discover)
import qualified Hedgehog

prop_legacy_and_forge_entries_can_be_interleaved :: Property
prop_legacy_and_forge_entries_can_be_interleaved = Hedgehog.property $ do
  credentials <- Hedgehog.evalEither $ decodeBulkCredentials "pools.json" $ BS8.pack $
    "[[" <> envelope "cert-0" <> "," <> envelope "vrf-0" <> "," <> envelope "kes-0" <> "],"
      <> "{\"version\":1,\"operationalCertificate\":" <> envelope "cert-1"
      <> ",\"vrfSigningKey\":" <> envelope "vrf-1"
      <> ",\"kesSource\":{\"type\":\"cardano-kes-forge\",\"connectionFile\":\"pool-1.json\"}}]"
  case credentials of
    [ BulkCredential{bulkKESSource = BulkKESFile _}
      , BulkCredential{bulkKESSource = BulkKESForge "pool-1.json"}
      ] -> pure ()
    _ -> Hedgehog.failure

prop_new_file_entry_is_explicit :: Property
prop_new_file_entry_is_explicit = Hedgehog.property $ do
  credentials <- Hedgehog.evalEither $ decodeBulkCredentials "pools.json" $ BS8.pack $
    "[{\"version\":1,\"operationalCertificate\":" <> envelope "cert"
      <> ",\"vrfSigningKey\":" <> envelope "vrf"
      <> ",\"kesSource\":{\"type\":\"file\",\"signingKey\":" <> envelope "kes" <> "}}]"
  case credentials of
    [BulkCredential{bulkKESSource = BulkKESFile _}] -> pure ()
    _ -> Hedgehog.failure

-- Exercise actual envelope deserialization and credential loading, not merely
-- the bulk grammar: both formats must apply the singleton key-binding policy.
prop_bulk_file_keys_must_match_the_operational_certificate :: Property
prop_bulk_file_keys_must_match_the_operational_certificate = Hedgehog.withTests 1 $ Hedgehog.property $ do
  kes <- Hedgehog.evalIO $ Api.generateSigningKey Api.AsKesKey
  otherKes <- Hedgehog.evalIO $ Api.generateSigningKey Api.AsKesKey
  cold <- Hedgehog.evalIO $ Api.generateSigningKey Api.AsStakePoolKey
  vrf <- Hedgehog.evalIO $ Api.generateSigningKey Api.AsVrfKey
  (certificate, _) <- Hedgehog.evalEither $
    Certificate.issueOperationalCertificate
      (Api.getVerificationKey kes)
      (Left $ Api.AnyStakePoolNormalSigningKey cold)
      (Certificate.KESPeriod 0)
      (Certificate.OperationalCertificateIssueCounter 0 $ Api.getVerificationKey cold)
  let certEnvelope = Api.serialiseToTextEnvelope Nothing certificate
      vrfEnvelope = Api.serialiseToTextEnvelope Nothing vrf
      entries key =
        let kesEnvelope = Api.serialiseToTextEnvelope Nothing key
        in [ Aeson.toJSON [certEnvelope, vrfEnvelope, kesEnvelope]
           , Aeson.object
               [ "version" Aeson..= (1 :: Int)
               , "operationalCertificate" Aeson..= certEnvelope
               , "vrfSigningKey" Aeson..= vrfEnvelope
               , "kesSource" Aeson..= Aeson.object
                   [ "type" Aeson..= ("file" :: String)
                   , "signingKey" Aeson..= kesEnvelope
                   ]
               ]
           ]
      load entry = do
        directory <- getTemporaryDirectory
        bracket
          (do
            (file, handle) <- openBinaryTempFile directory "kes-forge-bulk-binding.json"
            hClose handle
            pure file)
          removeFile
          (\file -> do
            LBS.writeFile file $ Aeson.encode [entry]
            result <- runExceptT $ readLeaderCredentials $
              Just $ ProtocolFilepaths Nothing Nothing Nothing Nothing Nothing (Just file)
            pure (file, result))
  forM_ (entries kes) $ \entry -> do
    (_, result) <- Hedgehog.evalIO $ load entry
    case result of
      Right [_] -> pure ()
      _ -> Hedgehog.failure
  forM_ (entries otherKes) $ \entry -> do
    (file, result) <- Hedgehog.evalIO $ load entry
    case result of
      Left (MismatchedKesKey keyLocation certificateLocation) -> do
        keyLocation Hedgehog.=== file <> "[0].kesSource.signingKey"
        certificateLocation Hedgehog.=== file <> "[0].operationalCertificate"
      _ -> Hedgehog.failure

prop_pretty_printed_bulk_credentials_are_accepted :: Property
prop_pretty_printed_bulk_credentials_are_accepted = Hedgehog.property $ do
  let pretty label =
        "{\"type\":\"" <> label <> "\",\n  \"description\":\"fixture\", \t\"cborHex\":\"00\"}"
      legacy = "[[\n" <> pretty "cert" <> ", \n" <> pretty "vrf" <> ",\n" <> pretty "kes" <> "\n]]"
      explicit = "[{\n \"version\":1,\n \"operationalCertificate\":" <> pretty "cert"
        <> ",\n \"vrfSigningKey\":" <> pretty "vrf"
        <> ",\n \"kesSource\":{\"type\":\"file\",\n \"signingKey\":" <> pretty "kes" <> "}}]"
  Hedgehog.assert $ isRight $ decodeBulkCredentials "legacy.json" $ BS8.pack legacy
  Hedgehog.assert $ isRight $ decodeBulkCredentials "explicit.json" $ BS8.pack explicit

prop_duplicate_keys_are_rejected_before_aeson_collapse :: Property
prop_duplicate_keys_are_rejected_before_aeson_collapse = Hedgehog.property $ do
  let input = "[{\"version\":1,\"\\u0076ersion\":1,\"operationalCertificate\":"
        <> envelope "cert" <> ",\"vrfSigningKey\":" <> envelope "vrf"
        <> ",\"kesSource\":{\"type\":\"cardano-kes-forge\",\"connectionFile\":\"pool.json\"}}]"
  Hedgehog.assert $ isLeft $ decodeBulkCredentials "pools.json" $ BS8.pack input

prop_invalid_new_entries_never_default_to_file :: Property
prop_invalid_new_entries_never_default_to_file = Hedgehog.property $ do
  let prefix = "[{\"version\":1,\"operationalCertificate\":" <> envelope "cert"
        <> ",\"vrfSigningKey\":" <> envelope "vrf" <> ",\"kesSource\":"
      suffix = "}]"
      invalidSources =
        [ "{\"type\":\"kes-agent\",\"connectionFile\":\"agent.sock\"}"
        , "{\"type\":\"cardano-kes-forge\",\"connectionFile\":\"\"}"
        , "{\"type\":\"cardano-kes-forge\"}"
        , "{\"type\":\"file\",\"connectionFile\":\"pool.json\"}"
        , "{\"type\":\"file\",\"signingKey\":" <> envelope "kes" <> ",\"connectionFile\":\"pool.json\"}"
        ]
  Hedgehog.assert $ all (isLeft . decodeBulkCredentials "pools.json" . BS8.pack . (prefix <>) . (<> suffix)) invalidSources

prop_malformed_legacy_triples_are_rejected :: Property
prop_malformed_legacy_triples_are_rejected = Hedgehog.property $ do
  Hedgehog.assert $ isLeft $ decodeBulkCredentials "pools.json" $ BS8.pack $
    "[[" <> envelope "cert" <> "," <> envelope "vrf" <> "]]"

prop_unsupported_versions_and_unknown_fields_are_rejected :: Property
prop_unsupported_versions_and_unknown_fields_are_rejected = Hedgehog.property $ do
  let body version extra =
        "[{\"version\":" <> version <> ",\"operationalCertificate\":" <> envelope "cert"
          <> ",\"vrfSigningKey\":" <> envelope "vrf"
          <> ",\"kesSource\":{\"type\":\"cardano-kes-forge\",\"connectionFile\":\"pool.json\"}"
          <> extra <> "]"
  Hedgehog.assert $ isLeft $ decodeBulkCredentials "pools.json" $ BS8.pack $ body "2" "}"
  Hedgehog.assert $ isLeft $ decodeBulkCredentials "pools.json" $ BS8.pack $ body "1" ",\"fallback\":true}"
prop_errors_are_entry_indexed_and_secret_free :: Property
prop_errors_are_entry_indexed_and_secret_free = Hedgehog.property $ do
  let badSource =
        "[[" <> envelope "cert-0" <> "," <> envelope "vrf-0" <> "," <> envelope "kes-0" <> "],"
          <> "{\"version\":1,\"operationalCertificate\":" <> envelope "private-cert-material"
          <> ",\"vrfSigningKey\":" <> envelope "private-vrf-material"
          <> ",\"kesSource\":{\"type\":\"kes-agent\",\"connectionFile\":\"secret.sock\"}}]"
  case decodeBulkCredentials "pools.json" $ BS8.pack badSource of
    Left err -> do
      Hedgehog.assert $ "pools.json[1].kesSource.type" `isInfixOf` err
      Hedgehog.assert $ not $ "private-cert-material" `isInfixOf` err
      Hedgehog.assert $ not $ "secret.sock" `isInfixOf` err
    Right _ -> Hedgehog.failure

  let duplicate =
        "[{}, {\"version\":1,\"version\":1,\"operationalCertificate\":"
          <> envelope "cert" <> ",\"vrfSigningKey\":" <> envelope "vrf"
          <> ",\"kesSource\":{\"type\":\"cardano-kes-forge\",\"connectionFile\":\"pool.json\"}}]"
  case decodeBulkCredentials "pools.json" $ BS8.pack duplicate of
    Left err -> Hedgehog.assert $ "pools.json[1]" `isInfixOf` err
    Right _ -> Hedgehog.failure

prop_duplicate_pool_identity_and_device_capacity_are_rejected :: Property
prop_duplicate_pool_identity_and_device_capacity_are_rejected = Hedgehog.property $ do
  let pool = BS8.replicate 28 'p'
  Hedgehog.assert $ isLeft $ validateCredentialIdentities [(pool, False), (pool, True)]
  Hedgehog.assert $ isRight $
    validateCredentialIdentities [(BS8.singleton $ toEnum index, False) | index <- [0 .. 32]]
  Hedgehog.assert $ isLeft $
    validateCredentialIdentities [(BS8.singleton $ toEnum index, True) | index <- [0 .. 32]]


prop_connection_config_is_strict_and_resolves_relative_socket :: Property
prop_connection_config_is_strict_and_resolves_relative_socket = Hedgehog.property $ do
  config <- Hedgehog.evalEither $ decodeKesForgePoolConfig "/etc/cardano/pool.json" $ BS8.pack validConnection
  kesForgePoolId config Hedgehog.=== BS8.replicate 28 '\x11'
  socketPath (kesForgeConnection config) Hedgehog.=== "/etc/cardano/kes.sock"
  deviceIdentity (kesForgeConnection config) Hedgehog.=== BS8.replicate 16 '\x22'
  poolIdentity (kesForgeConnection config) Hedgehog.=== BS8.replicate 28 '\x11'
  incarnationIdentity (kesForgeConnection config) Hedgehog.=== BS8.replicate 16 '\x33'
  networkMagic (networkBinding $ kesForgeConnection config) Hedgehog.=== 42
  securityPolicy (kesForgeConnection config) Hedgehog.=== PermitDevelopment

prop_connection_config_rejects_duplicates_unknowns_and_bad_lengths :: Property
prop_connection_config_rejects_duplicates_unknowns_and_bad_lengths = Hedgehog.property $ do
  Hedgehog.assert $ isLeft $ decodeKesForgePoolConfig "pool.json" $ BS8.pack $
    replaceOnce "\"version\":1" "\"version\":1,\"version\":1" validConnection
  Hedgehog.assert $ isLeft $ decodeKesForgePoolConfig "pool.json" $ BS8.pack $
    replaceOnce "\"securityPolicy\":\"isolated-development\"" "\"securityPolicy\":\"isolated-development\",\"fallback\":true" validConnection
  Hedgehog.assert $ isLeft $ decodeKesForgePoolConfig "pool.json" $ BS8.pack $
    replaceOnce (replicate 56 '1') (replicate 54 '1') validConnection

validConnection :: String
validConnection =
  "{\"version\":1,\"socketPath\":\"kes.sock\",\"deviceId\":\"" <> replicate 32 '2'
    <> "\",\"deviceIdentityFile\":\"device.json\",\"poolId\":\"" <> replicate 56 '1'
    <> "\",\"incarnationId\":\"" <> replicate 32 '3'
    <> "\",\"networkBinding\":{\"networkMagic\":42,\"shelleyGenesisDigest\":\"" <> replicate 64 '4'
    <> "\",\"slotsPerKesPeriod\":129600,\"maxKesEvolutions\":64},\"connectionName\":\"pool-a\""
    <> ",\"credentialFile\":\"pool.credential\",\"securityPolicy\":\"isolated-development\"}"

replaceOnce :: String -> String -> String -> String
replaceOnce needle replacement value =
  case breakOn needle value of
    Just (before, after) -> before <> replacement <> after
    Nothing -> value

breakOn :: String -> String -> Maybe (String, String)
breakOn needle = go []
 where
  go _ [] = Nothing
  go prefix remaining
    | take (length needle) remaining == needle =
        Just (reverse prefix, drop (length needle) remaining)
    | first : rest <- remaining = go (first : prefix) rest

prop_singleton_sources_are_selected_explicitly_and_mutually_exclusive :: Property
prop_singleton_sources_are_selected_explicitly_and_mutually_exclusive = Hedgehog.property $ do
  let selected arguments expected =
        case parseNode arguments of
          Success config ->
            (getLast (pncProtocolFiles config) >>= shelleyKESSource)
              Hedgehog.=== Just expected
          _ -> Hedgehog.failure
      rejected arguments =
        case parseNode arguments of
          Failure _ -> pure ()
          _ -> Hedgehog.failure
  selected ["--shelley-kes-key", "kes.skey"] $ KESKeyFilePath "kes.skey"
  selected ["--shelley-kes-agent-socket", "agent.sock"] $ KESAgentSocketPath "agent.sock"
  selected ["--shelley-kes-forge-config", "pool.json"] $ KESForgeConfigPath "pool.json"
  rejected
    [ "--shelley-kes-key", "kes.skey"
    , "--shelley-kes-forge-config", "pool.json"
    ]
  rejected
    [ "--shelley-kes-agent-socket", "agent.sock"
    , "--shelley-kes-forge-config", "pool.json"
    ]

parseNode :: [String] -> ParserResult PartialNodeConfiguration
parseNode sourceArguments =
  execParserPure defaultPrefs (info nodeCLIParser mempty) $
    [ "run"
    , "--config", "node.yaml"
    , "--topology", "topology.json"
    , "--database-path", "db"
    , "--socket-path", "node.socket"
    , "--shelley-operational-certificate", "node.cert"
    , "--shelley-vrf-key", "vrf.skey"
    ] <> sourceArguments

envelope :: String -> String
envelope label =
  "{\"type\":\"" <> label <> "\",\"description\":\"fixture\",\"cborHex\":\"00\"}"

isLeft :: Either a b -> Bool
isLeft Left{} = True
isLeft Right{} = False

tests :: IO Bool
tests = Hedgehog.checkParallel $$discover

isRight :: Either a b -> Bool
isRight Left{} = False
isRight Right{} = True
