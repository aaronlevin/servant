{-# LANGUAGE CPP                 #-}
{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies        #-}

module Servant.Server.Internal.Authentication
( AuthProtected (..)
, AuthData (..)
, AuthHandlers (AuthHandlers, onMissingAuthData, onUnauthenticated)
, basicAuthLax
, basicAuthStrict
, laxProtect
, strictProtect
, digestAuthCheck
, digestAuthStrict
        ) where

import           Control.Applicative              ((*>), (<$>), (<*), (<*>), (<|>))
import qualified Crypto.Hash.MD5                  as MD5
import           Crypto.Nonce                     as Nonce
import           Data.Attoparsec.ByteString.Char8 hiding (isSpace)
import qualified Data.Attoparsec.ByteString.Char8 as P (takeWhile)
import qualified Data.ByteString                  as B
import qualified Data.ByteString.Base16           as B16 (decode, encode)
import           Data.ByteString.Base64           (decodeLenient)
#if !MIN_VERSION_base(4,8,0)
import           Data.Monoid                      (mempty, (<>))
#else
import           Data.Monoid                      ((<>))
#endif
import           Control.Monad                    (guard)
import           Data.Char                        (isAlphaNum)
import           Data.Proxy                       (Proxy (Proxy))
import           Data.String                      (fromString)
import           Data.Word8                       (isSpace, toLower, _colon)
import           GHC.TypeLits                     (KnownSymbol, symbolVal)
import           Network.HTTP.Types.Status        (status401)
import           Network.Wai                      (Request, Response,
                                                   rawPathInfo, requestHeaders,
                                                   requestMethod,
                                                   responseBuilder)
import           Servant.API.Authentication       (AuthPolicy (Strict, Lax),
                                                   AuthProtected,
                                                   BasicAuth (BasicAuth),
                                                   DigestAuth (..), Algorithm (..))

-- | Class to represent the ability to extract authentication-related
-- data from a 'Request' object.
class AuthData a where
    authData :: Request -> Maybe a

-- | handlers to deal with authentication failures.
data AuthHandlers authData = AuthHandlers
    {   -- we couldn't find the right type of auth data (or any, for that matter)
        onMissingAuthData :: IO Response
    ,
        -- we found the right type of auth data in the request but the check failed
        onUnauthenticated :: authData -> IO Response
    }

-- | concrete type to provide when in 'Strict' mode.
data instance AuthProtected authData usr subserver 'Strict =
    AuthProtectedStrict { checkAuthStrict :: authData -> IO (Maybe usr)
                        , authHandlers :: AuthHandlers authData
                        , subServerStrict :: subserver
                        }

-- | concrete type to provide when in 'Lax' mode.
data instance AuthProtected authData usr subserver 'Lax =
    AuthProtectedLax { checkAuthLax :: authData -> IO (Maybe usr)
                     , subServerLax :: subserver
                     }

-- | handy function to build an auth-protected bit of API with a 'Lax' policy
laxProtect :: (authData -> IO (Maybe usr)) -- ^ check auth
           -> subserver                    -- ^ the handlers for the auth-aware bits of the API
           -> AuthProtected authData usr subserver 'Lax
laxProtect = AuthProtectedLax

-- | handy function to build an auth-protected bit of API with a 'Strict' policy
strictProtect :: (authData -> IO (Maybe usr)) -- ^ check auth
              -> AuthHandlers authData        -- ^ functions to call on auth failure
              -> subserver                    -- ^ handlers for the auth-protected bits of the API
              -> AuthProtected authData usr subserver 'Strict
strictProtect = AuthProtectedStrict

-- | 'BasicAuth' instance for authData
instance AuthData (BasicAuth realm) where
    authData request = do
        authBs <- lookup "Authorization" (requestHeaders request)
        let (x,y) = B.break isSpace authBs
        guard (B.map toLower x == "basic")
        -- decode the base64-encoded username and password
        let (username, passWithColonAtHead) = B.break (== _colon) (decodeLenient (B.dropWhile isSpace y))
        (_, password) <- B.uncons passWithColonAtHead
        return $ BasicAuth username password

-- | handlers for Basic Authentication.
basicAuthHandlers :: forall realm. KnownSymbol realm => AuthHandlers (BasicAuth realm)
basicAuthHandlers =
    let realmBytes = (fromString . symbolVal) (Proxy :: Proxy realm)
        headerBytes = "Basic realm=\"" <> realmBytes <> "\""
        authFailure = responseBuilder status401 [("WWW-Authenticate", headerBytes)] mempty in
        AuthHandlers (return authFailure)  ((const . return) authFailure)

-- | Basic authentication combinator with strict failure.
basicAuthStrict :: KnownSymbol realm
                => (BasicAuth realm -> IO (Maybe usr))
                -> subserver
                -> AuthProtected (BasicAuth realm) usr subserver 'Strict
basicAuthStrict check subserver = strictProtect check basicAuthHandlers subserver

-- | Basic authentication combinator with lax failure.
basicAuthLax :: KnownSymbol realm
             => (BasicAuth realm -> IO (Maybe usr))
             -> subserver
             -> AuthProtected (BasicAuth realm) usr subserver 'Lax
basicAuthLax = laxProtect

parseAlgorithm :: B.ByteString -> Maybe Algorithm
parseAlgorithm "MD5" = Just MD5
parseAlgorithm _ = Nothing

-- | Creates an MD5 hash of @input@ and returns a 32-digit hex string
md5 :: [B.ByteString] -> B.ByteString
md5 = B16.encode . MD5.hash . B.intercalate ":"

instance AuthData (DigestAuth realm) where
  authData request = do
    authBs <- lookup "Authorization" (requestHeaders request)
    case parseOnly parseAuthorizationHeader authBs of
      Left a -> Nothing
      Right vals -> do
        username <- lookup "username" vals
        realm <- lookup "realm" vals
        nonce <- lookup "nonce" vals
        digestURI <- lookup "uri" vals
        response <- lookup "response" vals
        let algorithm = maybe MD5 id $ parseAlgorithm =<< lookup "algorithm" vals
        let cnonce = lookup "cnonce" vals
        let opaque = lookup "opaque" vals
        let qop = lookup "qop" vals
        let nonceCount = lookup "nc" vals
        let method = requestMethod request
        return $ DigestAuth username realm nonce digestURI method response algorithm cnonce opaque qop nonceCount

parseAuthorizationHeader :: Parser [(B.ByteString, B.ByteString)]
parseAuthorizationHeader = (string "Digest") *> space *> props
  where props = sepBy1 prop comma
        comma = many' space *> char ',' *> many' space
        prop  = (,) <$> (word <* char '=') <*> (quotedString <|> word)
        word  = takeWhile1 (\x -> (isAlphaNum x) || x =='_' || x == '.' || x=='-' || x ==':')
        quotedString = char '"' *> P.takeWhile (not . (=='"')) <* char '"'

digestAuthCheck :: forall realm user. KnownSymbol realm
                => (user -> B.ByteString) -- ^ How to get the MD5(user:realm:passwd) hash
                -> (DigestAuth realm -> IO (Maybe user)) -- ^ Lookup a user given the username
                -> (DigestAuth realm -> IO (Maybe user))
digestAuthCheck ha1 lookupUser authData = do
  maybeUser <- lookupUser authData
  let realmBytes = (fromString . symbolVal $ (Proxy :: Proxy realm))
  return $ do
    user <- maybeUser
    guard $ daRealm authData == realmBytes
    -- currently only MD5 algorithm is supported. So we can assume algorithm is that

    let ha2 = md5 [daMethod authData, daDigestURI authData]
    response <-
      case daQop authData of
        Just "auth" -> do
          nc <- daNonceCount authData
          cn <- daCNonce authData
          return $ md5 [ha1 user, daNonce authData, nc, cn, "auth", ha2]

        Just _  -> Nothing
        Nothing ->
          return $ md5 [ha1 user, daNonce authData, ha2]

    guard $ response == daResponse authData
    return user

digestAuthHandlers :: forall realm. KnownSymbol realm => AuthHandlers (DigestAuth realm)
digestAuthHandlers = AuthHandlers onMissingAuthData (const onMissingAuthData)
  where
    onMissingAuthData = do
      g <- Nonce.new
      nonce <- B16.encode <$> Nonce.nonce128 g
      opaque <- B16.encode <$> Nonce.nonce128 g
      let realmBytes = (fromString . symbolVal) (Proxy :: Proxy realm)
      let headerBytes = "Digest realm=\"" <> realmBytes <> "\",nonce=\""<>nonce<>"\",opaque=\""<>opaque<>"\""
      return $ responseBuilder status401 [("WWW-Authenticate", headerBytes)] mempty

digestAuthStrict ha1 lookup subserver = strictProtect (digestAuthCheck ha1 lookup) digestAuthHandlers subserver
