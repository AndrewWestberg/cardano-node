{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Cardano.Node.Protocol.Shelley.Credentials
  ( BulkCredential (..)
  , BulkKESSource (..)
  , decodeBulkCredentials
  ) where

import Cardano.Api (TextEnvelope)
import Data.Aeson (FromJSON (..), Value (..), (.:), (.:?), (.!=), withObject)
import qualified Data.Aeson as Aeson
import Data.Aeson.Decoding.ByteString (bsToTokens)
import Data.Aeson.Decoding.Tokens
  ( TkArray (..)
  , TkRecord (..)
  , Tokens (..)
  )
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import Data.Aeson.Types (Parser)
import qualified Data.ByteString as BS
import Data.Char (isSpace)
import qualified Data.Set as Set
import qualified Data.Text as Text
import System.FilePath (isAbsolute, normalise, takeDirectory, (</>))

-- | One independently selected bulk credential source. Legacy array entries
-- and version-1 object entries decode to this common representation.
data BulkCredential = BulkCredential
  { bulkOperationalCertificate :: !TextEnvelope
  , bulkVrfSigningKey :: !TextEnvelope
  , bulkKesSource :: !BulkKESSource
  , bulkBlsSigningKeys :: ![TextEnvelope]
  }
  deriving (Eq, Show)

data BulkKESSource
  = BulkKESFile !TextEnvelope
  | BulkKESAgent !FilePath
  deriving (Eq, Show)

instance FromJSON BulkCredential where
  parseJSON = \case
    Array values ->
      case foldr (:) [] values of
        [certificate, vrf, kes] ->
          BulkCredential
            <$> parseJSON certificate
            <*> parseJSON vrf
            <*> (BulkKESFile <$> parseJSON kes)
            <*> pure []
        [certificate, vrf, kes, bls] ->
          BulkCredential
            <$> parseJSON certificate
            <*> parseJSON vrf
            <*> (BulkKESFile <$> parseJSON kes)
            <*> parseLegacyBls bls
        _ -> fail "Expected a legacy bulk credential entry with 3 or 4 elements"
    value@(Object _) -> withObject "versioned bulk credential" parseVersioned value
    _ -> fail "Expected a legacy array or versioned bulk credential object"
   where
    parseVersioned object = do
      rejectUnknown
        "versioned bulk credential"
        ["version", "operationalCertificate", "vrfSigningKey", "kesSource", "blsSigningKeys"]
        object
      version <- object .: "version"
      if (version :: Int) /= 1
        then fail "Unsupported bulk credential version"
        else
          BulkCredential
            <$> object .: "operationalCertificate"
            <*> object .: "vrfSigningKey"
            <*> object .: "kesSource"
            <*> (object .:? "blsSigningKeys" .!= [])

instance FromJSON BulkKESSource where
  parseJSON = withObject "KES credential source" $ \object -> do
    sourceType <- object .: "type"
    case (sourceType :: Text.Text) of
      "file" -> do
        rejectUnknown "file KES source" ["type", "signingKey"] object
        BulkKESFile <$> object .: "signingKey"
      "kes-agent" -> do
        rejectUnknown "KES agent source" ["type", "socketPath"] object
        path <- object .: "socketPath"
        if null path
          then fail "KES agent socketPath must not be empty"
          else pure (BulkKESAgent path)
      _ -> fail "Unsupported KES credential source type"

parseLegacyBls :: Value -> Parser [TextEnvelope]
parseLegacyBls Null = pure []
parseLegacyBls value@(Array _) = parseJSON value
parseLegacyBls value = (: []) <$> parseJSON value

rejectUnknown :: String -> [Text.Text] -> Aeson.Object -> Parser ()
rejectUnknown label allowed object =
  case filter (`notElem` allowed) (Key.toText <$> KeyMap.keys object) of
    [] -> pure ()
    unknown -> fail $ label <> " contains unknown field(s): " <> show unknown

-- | Decode the complete file while retaining JSON object key occurrences long
-- enough to reject duplicates before Aeson normalizes an object into a map.
decodeBulkCredentials :: FilePath -> BS.ByteString -> Either String [BulkCredential]
decodeBulkCredentials bulkFile bytes = do
  remainder <- checkValue (bsToTokens bytes)
  if BS.all (isSpace . toEnum . fromIntegral) remainder
    then pure ()
    else Left "Trailing bytes after bulk credentials JSON"
  credentials <- Aeson.eitherDecodeStrict' bytes
  traverse resolveCredential credentials
 where
  resolveCredential credential@BulkCredential{bulkKesSource = BulkKESAgent path} =
    let resolved
          | isAbsolute path = normalise path
          | otherwise = normalise (takeDirectory bulkFile </> path)
     in Right credential{bulkKesSource = BulkKESAgent resolved}
  resolveCredential credential = Right credential

checkValue :: Tokens continuation String -> Either String continuation
checkValue = \case
  TkLit _ continuation -> Right continuation
  TkText _ continuation -> Right continuation
  TkNumber _ continuation -> Right continuation
  TkArrayOpen array -> checkArray array
  TkRecordOpen record -> checkRecord Set.empty record
  TkErr err -> Left err

checkArray :: TkArray continuation String -> Either String continuation
checkArray = \case
  TkItem value -> checkValue value >>= checkArray
  TkArrayEnd continuation -> Right continuation
  TkArrayErr err -> Left err

checkRecord :: Set.Set Text.Text -> TkRecord continuation String -> Either String continuation
checkRecord seen = \case
  TkPair key value
    | keyText `Set.member` seen -> Left $ "Duplicate JSON object key: " <> Text.unpack keyText
    | otherwise -> checkValue value >>= checkRecord (Set.insert keyText seen)
   where
    keyText = Key.toText key
  TkRecordEnd continuation -> Right continuation
  TkRecordErr err -> Left err
