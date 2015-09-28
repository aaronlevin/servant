module Servant.API.Authentication.Internal
  ( DigestAuth (..)
  ) where

data Algorithm = MD5 deriving (Eq, Show, Typeable)

data Qop = Qop
  { qCNonce     :: ByteString
  , qNonceCount :: ByteString
  }

data DigestAuth (realm :: Symbol) =
  DigestAuth
    { daUsername    :: ByteString
    , daNonce       :: ByteString
    , daDigestURI   :: ByteString
    , daMethod      :: ByteString
    , daResponse    :: ByteString
    , daAlgorithm   :: Algorithm
    , daQop         :: Maybe Qop
    }



