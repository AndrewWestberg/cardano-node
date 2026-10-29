{-# LANGUAGE OverloadedStrings #-}

module Test.Cardano.Node.BulkCredentials
  ( tests
  ) where

import Cardano.Node.Protocol.Shelley.Credentials
import qualified Data.ByteString.Char8 as BS8
import Hedgehog

fixtureEnvelope :: String
fixtureEnvelope = "{\"type\":\"fixture\",\"description\":\"\",\"cborHex\":\"00\"}"

prop_mixedLegacyFileAndAgent :: Property
prop_mixedLegacyFileAndAgent = withTests 1 $ property $ do
  let legacy = "[" <> fixtureEnvelope <> "," <> fixtureEnvelope <> "," <> fixtureEnvelope <> "]"
      versionedFile =
        "{\"version\":1,\"operationalCertificate\":" <> fixtureEnvelope
          <> ",\"vrfSigningKey\":" <> fixtureEnvelope
          <> ",\"kesSource\":{\"type\":\"file\",\"signingKey\":" <> fixtureEnvelope <> "}}"
      versionedAgent =
        "{\"version\":1,\"operationalCertificate\":" <> fixtureEnvelope
          <> ",\"vrfSigningKey\":" <> fixtureEnvelope
          <> ",\"kesSource\":{\"type\":\"kes-agent\",\"socketPath\":\"agents/pool.sock\"}}"
      input = BS8.pack $ "[" <> legacy <> "," <> versionedFile <> "," <> versionedAgent <> "]"
  credentials <- evalEither $ decodeBulkCredentials "/etc/cardano/bulk.json" input
  length credentials === 3
  case bulkKesSource (credentials !! 2) of
    BulkKESAgent path -> path === "/etc/cardano/agents/pool.sock"
    _ -> failure

prop_absoluteAgentPathIsNotRebased :: Property
prop_absoluteAgentPathIsNotRebased = withTests 1 $ property $ do
  let input = BS8.pack $
        "[{\"version\":1,\"operationalCertificate\":" <> fixtureEnvelope
          <> ",\"vrfSigningKey\":" <> fixtureEnvelope
          <> ",\"kesSource\":{\"type\":\"kes-agent\",\"socketPath\":\"/run/kes/pool.sock\"}}]"
  credentials <- evalEither $ decodeBulkCredentials "/etc/cardano/bulk.json" input
  case credentials of
    [credential] -> case bulkKesSource credential of
      BulkKESAgent path -> path === "/run/kes/pool.sock"
      _ -> failure
    _ -> failure

prop_rejectsDuplicateAndUnknownFields :: Property
prop_rejectsDuplicateAndUnknownFields = withTests 1 $ property $ do
  let prefix = "[{\"version\":1,\"version\":1,\"operationalCertificate\":"
      duplicate = BS8.pack $
        prefix <> fixtureEnvelope <> ",\"vrfSigningKey\":" <> fixtureEnvelope
          <> ",\"kesSource\":{\"type\":\"kes-agent\",\"socketPath\":\"pool.sock\"}}]"
      unknown = BS8.pack $
        "[{\"version\":1,\"operationalCertificate\":" <> fixtureEnvelope
          <> ",\"vrfSigningKey\":" <> fixtureEnvelope
          <> ",\"kesSource\":{\"type\":\"kes-agent\",\"socketPath\":\"pool.sock\",\"fallback\":"
          <> fixtureEnvelope <> "}}]"
  assert $ either (const True) (const False) $ decodeBulkCredentials "bulk.json" duplicate
  assert $ either (const True) (const False) $ decodeBulkCredentials "bulk.json" unknown

prop_rejectsUnsupportedOrEmptySources :: Property
prop_rejectsUnsupportedOrEmptySources = withTests 1 $ property $ do
  let entry source = BS8.pack $
        "[{\"version\":1,\"operationalCertificate\":" <> fixtureEnvelope
          <> ",\"vrfSigningKey\":" <> fixtureEnvelope
          <> ",\"kesSource\":" <> source <> "}]"
  assert $ either (const True) (const False) $
    decodeBulkCredentials "bulk.json" $ entry "{\"type\":\"agent\",\"socketPath\":\"pool.sock\"}"
  assert $ either (const True) (const False) $
    decodeBulkCredentials "bulk.json" $ entry "{\"type\":\"kes-agent\",\"socketPath\":\"\"}"

tests :: IO Bool
tests = checkParallel $ Group "bulk credentials"
  [ ("mixed legacy/file/agent", prop_mixedLegacyFileAndAgent)
  , ("absolute agent path", prop_absoluteAgentPathIsNotRebased)
  , ("duplicate and unknown fields", prop_rejectsDuplicateAndUnknownFields)
  , ("unsupported sources", prop_rejectsUnsupportedOrEmptySources)
  ]
