{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Cardano.Node.Protocol.Shelley.Credentials
  ( BulkCredential (..)
  , BulkKESSource (..)
  , decodeBulkCredentials
  , rejectDuplicateKeys
  ) where

import Cardano.Api (TextEnvelope)

import Control.Monad (unless, when)
import Data.Aeson (Value (..), eitherDecodeStrict', parseJSON)
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import Data.Aeson.Types (parseEither)
import qualified Data.ByteString as BS
import Data.Char (isDigit)
import Data.List (isPrefixOf)
import qualified Data.Set as Set
import qualified Data.Text as Text
import qualified Data.Vector as Vector

-- | One independently configured bulk forging credential. Legacy triples are
-- represented as a file source so the existing wire format retains its exact
-- meaning.
data BulkCredential = BulkCredential
  { bulkOperationalCertificate :: !TextEnvelope
  , bulkVrfSigningKey :: !TextEnvelope
  , bulkKESSource :: !BulkKESSource
  }
  deriving (Eq, Show)

data BulkKESSource
  = BulkKESFile !TextEnvelope
  | BulkKESForge !FilePath
  deriving (Eq, Show)

-- | Decode the legacy/new union without allowing JSON object duplicate keys.
-- Aeson intentionally keeps one value for a duplicate key, so the raw syntax
-- is checked before ordinary value decoding.
decodeBulkCredentials :: FilePath -> BS.ByteString -> Either String [BulkCredential]
decodeBulkCredentials file bytes = do
  either (Left . qualify file) Right $ rejectDuplicateKeys bytes
  value <- eitherDecodeStrict' bytes
  entries <- case value of
    Array xs -> Right xs
    _ -> Left "bulk credentials must be a JSON array"
  traverse (uncurry (parseEntry file)) (zip [0 :: Int ..] (Vector.toList entries))

parseEntry :: FilePath -> Int -> Value -> Either String BulkCredential
parseEntry file index = \case
  Array xs
    | [cert, vrf, kes] <- Vector.toList xs ->
        BulkCredential
          <$> envelope "operationalCertificate" cert
          <*> envelope "vrfSigningKey" vrf
          <*> (BulkKESFile <$> envelope "kesSigningKey" kes)
    | otherwise -> atEntry "legacy credential must contain exactly three envelopes"
  Object object -> do
    either atEntry pure $ exactKeys ["version", "operationalCertificate", "vrfSigningKey", "kesSource"] object
    version <- required "version" object >>= parseAt "version"
    unless (version == (1 :: Integer)) $ atField "version" "unsupported version"
    cert <- required "operationalCertificate" object >>= envelope "operationalCertificate"
    vrf <- required "vrfSigningKey" object >>= envelope "vrfSigningKey"
    sourceValue <- required "kesSource" object
    source <- parseSource file index sourceValue
    pure $ BulkCredential cert vrf source
  _ -> atEntry "credential must be a legacy triple or versioned object"
 where
  atEntry message = Left $ location file index <> ": " <> message
  atField name message = Left $ location file index <> "." <> name <> ": " <> message
  envelope name = either (atField name) Right . parseAt name
  parseAt name = either (Left . ((location file index <> "." <> name <> ": ") <>)) Right . parseEither parseJSON
  required name = either (atField $ Key.toString name) Right . field name

parseSource :: FilePath -> Int -> Value -> Either String BulkKESSource
parseSource file index = \case
  Object object -> do
    sourceType <- required "type" object >>= parseAt "type"
    case (sourceType :: Text.Text) of
      "file" -> do
        either atSource pure $ exactKeys ["type", "signingKey"] object
        BulkKESFile <$> (required "signingKey" object >>= envelope "signingKey")
      "cardano-kes-forge" -> do
        either atSource pure $ exactKeys ["type", "connectionFile"] object
        path <- required "connectionFile" object >>= parseAt "connectionFile"
        if null path
          then atField "connectionFile" "path must not be empty"
          else pure $ BulkKESForge path
      "kes-agent" -> atField "type" "kes-agent is not supported in bulk credentials"
      _ -> atField "type" "unsupported KES source"
  _ -> atField "kesSource" "source must be an object"
 where
  atSource message = Left $ location file index <> ".kesSource: " <> message
  atField name message = Left $ location file index <> ".kesSource." <> name <> ": " <> message
  envelope name = either (atField name) Right . parseAt name
  parseAt name = either (Left . ((location file index <> ".kesSource." <> name <> ": ") <>)) Right . parseEither parseJSON
  required name = either (atField $ Key.toString name) Right . field name

field :: Key.Key -> KeyMap.KeyMap Value -> Either String Value
field name object = maybe (Left $ "missing field " <> Key.toString name) Right $ KeyMap.lookup name object

exactKeys :: [Key.Key] -> KeyMap.KeyMap Value -> Either String ()
exactKeys expected object =
  unless (Set.fromList (KeyMap.keys object) == Set.fromList expected) $
    Left "object contains missing or unknown fields"

location :: FilePath -> Int -> String
location file index = file <> "[" <> show index <> "]"
qualify :: FilePath -> String -> String
qualify file message
  | "[" `isPrefixOf` message = file <> message
  | otherwise = file <> ": " <> message


rejectDuplicateKeys :: BS.ByteString -> Either String ()
rejectDuplicateKeys bytes = do
  end <- value "" 0
  finish end
 where
  lengthBytes = BS.length bytes

  finish offset
    | skipSpace offset == lengthBytes = Right ()
    | otherwise = Left "trailing bytes after JSON value"

  value path offset =
    case byte (skipSpace offset) of
      Just 123 -> object path (skipSpace offset + 1)
      Just 91 -> array path (skipSpace offset + 1)
      Just 34 -> snd <$> stringToken (skipSpace offset)
      Just 116 -> literal "true" (skipSpace offset)
      Just 102 -> literal "false" (skipSpace offset)
      Just 110 -> literal "null" (skipSpace offset)
      Just c | c == 45 || isDigit (toEnum $ fromIntegral c) -> number (skipSpace offset)
      _ -> Left "invalid JSON value"

  object path offset = go Set.empty (skipSpace offset)
   where
    go seen current = case byte current of
      Just 125 -> Right (current + 1)
      Just 34 -> do
        (rawKey, afterKey) <- stringToken current
        key <- eitherDecodeStrict' rawKey :: Either String Text.Text
        when (Set.member key seen) $
          Left $ prefix path <> "duplicate JSON object key: " <> Text.unpack key
        colon <- expect 58 (skipSpace afterKey)
        afterValue <- value (fieldPath path key) (colon + 1)
        let end = skipSpace afterValue
        case byte end of
          Just 44 -> go (Set.insert key seen) (skipSpace $ end + 1)
          Just 125 -> Right (end + 1)
          _ -> Left "expected ',' or '}' in JSON object"
      _ -> Left "expected object key"

  array path offset = go (0 :: Int) (skipSpace offset)
   where
    go index current = case byte current of
      Just 93 -> Right (current + 1)
      _ -> do
        afterValue <- value (path <> "[" <> show index <> "]") current
        case byte (skipSpace afterValue) of
          Just 44 -> go (index + 1) (skipSpace afterValue + 1)
          Just 93 -> Right (skipSpace afterValue + 1)
          _ -> Left "expected ',' or ']' in JSON array"

  prefix "" = ""
  prefix path = path <> ": "

  fieldPath "" key = Text.unpack key
  fieldPath path key = path <> "." <> Text.unpack key

  stringToken start = go (start + 1)
   where
    go current = case byte current of
      Nothing -> Left "unterminated JSON string"
      Just 34 -> Right (BS.take (current - start + 1) $ BS.drop start bytes, current + 1)
      Just 92 -> case byte (current + 1) of
        Just 117
          | current + 5 < lengthBytes
          , BS.all isHex $ BS.take 4 $ BS.drop (current + 2) bytes -> go (current + 6)
        Just escaped
          | escaped `elem` [34, 47, 92, 98, 102, 110, 114, 116] -> go (current + 2)
        _ -> Left "invalid JSON string escape"
      Just c
        | c < 32 -> Left "control byte in JSON string"
        | otherwise -> go (current + 1)

  number start = do
    let end = scanNumber start
        token = BS.take (end - start) $ BS.drop start bytes
    _ <- eitherDecodeStrict' token :: Either String Value
    Right end

  scanNumber current = case byte current of
    Just c | c `elem` [43, 45, 46, 69, 101] || (c >= 48 && c <= 57) -> scanNumber (current + 1)
    _ -> current

  literal expected start
    | expected == BS.take (BS.length expected) (BS.drop start bytes) = Right $ start + BS.length expected
    | otherwise = Left "invalid JSON literal"

  expect wanted offset = case byte offset of
    Just actual | actual == wanted -> Right offset
    _ -> Left "invalid JSON separator"

  byte offset
    | offset < lengthBytes = Just $ BS.index bytes offset
    | otherwise = Nothing

  skipSpace offset = case byte offset of
    Just c | c `elem` [9, 10, 13, 32] -> skipSpace (offset + 1)
    _ -> offset

  isHex c =
    (c >= 48 && c <= 57)
      || (c >= 65 && c <= 70)
      || (c >= 97 && c <= 102)
