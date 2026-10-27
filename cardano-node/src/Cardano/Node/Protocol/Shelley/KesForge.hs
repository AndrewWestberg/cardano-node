{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}

module Cardano.Node.Protocol.Shelley.KesForge
  ( KesForgePoolConfig (..)
  , decodeKesForgePoolConfig
  ) where

import Control.Monad (unless, when)
import Cardano.Node.Protocol.Shelley.Credentials (rejectDuplicateKeys)

import Data.Aeson (FromJSON, Value (Object), eitherDecodeStrict', parseJSON)
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import Data.Aeson.Types (parseEither)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.Set as Set
import qualified Data.Text.Encoding as Text
import Data.Word (Word32, Word64)
import qualified Ouroboros.Consensus.Protocol.KesForge.Client as KesForge
import System.FilePath (isAbsolute, normalise, takeDirectory, (</>))

data KesForgePoolConfig = KesForgePoolConfig
  { kesForgeConnection :: !KesForge.Connection
  , kesForgePoolId :: !BS.ByteString
  }
  deriving (Eq, Show)


decodeKesForgePoolConfig :: FilePath -> BS.ByteString -> Either String KesForgePoolConfig
decodeKesForgePoolConfig file bytes = do
  either (Left . ((file <> ": ") <>)) Right $ rejectDuplicateKeys bytes
  value <- eitherDecodeStrict' bytes
  object <- case value of
    Object fields -> Right fields
    _ -> Left $ file <> ": connection config must be an object"
  either (Left . ((file <> ": ") <>)) Right $
    exactKeys
      [ "version"
      , "socketPath"
      , "deviceId"
      , "deviceIdentityFile"
      , "poolId"
      , "incarnationId"
      , "networkBinding"
      , "connectionName"
      , "credentialFile"
      , "securityPolicy"
      ]
      object
  version <- required file "version" object
  unless (version == (1 :: Word64)) $ invalid "version" "unsupported version"
  socket <- nonemptyPath "socketPath" object
  device <- fixedHex "deviceId" 16 object
  _identity <- nonemptyPath "deviceIdentityFile" object
  pool <- fixedHex "poolId" 28 object
  incarnation <- fixedHex "incarnationId" 16 object
  networkValue <- field file "networkBinding" object
  network <- parseNetwork networkValue
  name <- required file "connectionName" object
  unless (validConnection name) $ invalid "connectionName" "invalid connection name"
  _credential <- nonemptyPath "credentialFile" object
  policyName <- required file "securityPolicy" object
  policy <- case policyName :: String of
    "isolated-development" -> Right KesForge.PermitDevelopment
    "release-required" -> Right KesForge.RequireRelease
    _ -> invalid "securityPolicy" "unsupported security policy"
  pure KesForgePoolConfig
    { kesForgeConnection =
        KesForge.Connection
          { KesForge.socketPath = resolve file socket
          , KesForge.connectionName = name
          , KesForge.networkBinding = network
          , KesForge.deviceIdentity = device
          , KesForge.poolIdentity = pool
          , KesForge.incarnationIdentity = incarnation
          , KesForge.securityPolicy = policy
          }
    , kesForgePoolId = pool
    }
 where
  invalid name message = Left $ file <> "." <> Key.toString name <> ": " <> message
  nonemptyPath name object = do
    path <- required file name object
    if null (path :: FilePath)
      then invalid name "path must not be empty"
      else Right path
  fixedHex name size object = do
    encoded <- required file name object
    decoded <- either (const $ invalid name "invalid hexadecimal value") Right $
      Base16.decode $ Text.encodeUtf8 encoded
    if BS.length decoded == size
      then Right decoded
      else invalid name $ "expected " <> show size <> " bytes"

  parseNetwork (Object object) = do
    either (invalid "networkBinding") Right $
      exactKeys ["networkMagic", "shelleyGenesisDigest", "slotsPerKesPeriod", "maxKesEvolutions"] object
    magic <- required (file <> ".networkBinding") "networkMagic" object
    when (magic > fromIntegral (maxBound :: Word32)) $
      invalid "networkBinding.networkMagic" "value exceeds Word32"
    digest <- fixedNetworkHex "shelleyGenesisDigest" 32 object
    slots <- required (file <> ".networkBinding") "slotsPerKesPeriod" object
    evolutions <- required (file <> ".networkBinding") "maxKesEvolutions" object
    when (slots == 0) $ invalid "networkBinding.slotsPerKesPeriod" "must be positive"
    when (evolutions == 0) $ invalid "networkBinding.maxKesEvolutions" "must be positive"
    pure KesForge.NetworkBinding
      { KesForge.networkMagic = magic
      , KesForge.shelleyGenesisDigest = digest
      , KesForge.slotsPerKESPeriod = slots
      , KesForge.maxKESEvolutions = evolutions
      }
  parseNetwork _ = invalid "networkBinding" "must be an object"

  fixedNetworkHex name size object = do
    encoded <- required (file <> ".networkBinding") name object
    decoded <- either (const $ invalid ("networkBinding." <> name) "invalid hexadecimal value") Right $
      Base16.decode $ Text.encodeUtf8 encoded
    if BS.length decoded == size
      then Right decoded
      else invalid ("networkBinding." <> name) $ "expected " <> show size <> " bytes"

required :: FromJSON a => FilePath -> Key.Key -> KeyMap.KeyMap Value -> Either String a
required location name object =
  field location name object
    >>= either
      (Left . ((location <> "." <> Key.toString name <> ": ") <>))
      Right
      . parseEither parseJSON

field :: FilePath -> Key.Key -> KeyMap.KeyMap Value -> Either String Value
field location name object =
  maybe (Left $ location <> "." <> Key.toString name <> ": missing field") Right $
    KeyMap.lookup name object

exactKeys :: [Key.Key] -> KeyMap.KeyMap Value -> Either String ()
exactKeys expected object =
  unless (Set.fromList (KeyMap.keys object) == Set.fromList expected) $
    Left "object contains missing or unknown fields"

resolve :: FilePath -> FilePath -> FilePath
resolve containing path
  | isAbsolute path = normalise path
  | otherwise = normalise $ takeDirectory containing </> path

validConnection :: String -> Bool
validConnection name =
  not (null name)
    && length name <= 64
    && all valid name
 where
  valid c =
    c >= '0' && c <= '9'
      || c >= 'A' && c <= 'Z'
      || c >= 'a' && c <= 'z'
      || c `elem` ("-_." :: String)
