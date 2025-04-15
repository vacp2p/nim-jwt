import json, strutils, tables, times
import bearssl

from jwt/private/crypto import nil

import jwt/private/[claims, jose, utils]

type
  InvalidToken* = object of ValueError

  JWT* = object
    headerB64: string
    claimsB64: string
    header*: JsonNode
    claims*: TableRef[string, Claim]
    signature*: seq[byte]

export claims
export jose

proc splitToken(s: string): seq[string] =
  let parts = s.split(".")
  if parts.len != 3:
    raise newException(InvalidToken, "Invalid token")
  result = parts

proc initJWT*(
    header: JsonNode, claims: TableRef[string, Claim], signature: seq[byte] = @[]
): JWT =
  JWT(
    headerB64: header.toBase64,
    claimsB64: claims.toBase64,
    header: header,
    claims: claims,
    signature: signature,
  )

# Load up a b64url string to JWT
proc toJWT*(s: string): JWT =
  var parts = splitToken(s)
  let
    headerB64 = parts[0]
    claimsB64 = parts[1]
    headerJson = parseJson(decodeUrlSafeAsString(headerB64))
    claimsJson = parseJson(decodeUrlSafeAsString(claimsB64))
    signature = decodeUrlSafe(parts[2])

  JWT(
    headerB64: headerB64,
    claimsB64: claimsB64,
    header: headerJson.toHeader(),
    claims: claimsJson.toClaims(),
    signature: signature,
  )

proc toJWT*(node: JsonNode): JWT =
  initJWT(node["header"].toHeader, node["claims"].toClaims)

# Encodes the raw signature to b64url
proc signatureToB64(token: JWT): string =
  assert token.signature.len != 0
  result = encodeUrlSafe(token.signature)

proc loaded*(token: JWT): string =
  token.headerB64 & "." & token.claimsB64

proc parsed*(token: JWT): string =
  result = token.header.toBase64 & "." & token.claims.toBase64

# Signs a string with a secret
proc signString*(
    toSign: string, secret: string, algorithm: SignatureAlgorithm = HS256
): seq[byte] =
  template hsSign(meth: typed): seq[byte] =
    crypto.bearHMAC(addr meth, secret, toSign)

  template rsSign(hc, oid: typed, hashLen: int): seq[byte] =
    crypto.bearSignRSPem(toSign, secret, addr hc, oid, hashLen)

  template ecSign(hc: typed): seq[byte] =
    crypto.bearSignECPem(toSign, secret, addr hc)

  case algorithm
  of HS256:
    return hsSign(sha256Vtable)
  of HS384:
    return hsSign(sha384Vtable)
  of HS512:
    return hsSign(sha512Vtable)
  of RS256:
    return rsSign(sha256Vtable, HASH_OID_SHA256, sha256SIZE)
  of RS384:
    return rsSign(sha384Vtable, HASH_OID_SHA384, sha384SIZE)
  of RS512:
    return rsSign(sha512Vtable, HASH_OID_SHA512, sha512SIZE)
  of ES256:
    return ecSign(sha256Vtable)
  of ES384:
    return ecSign(sha384Vtable)
  of ES512:
    return ecSign(sha512Vtable)

  # of ES384:
  #   return rsSign(crypto.EVP_sha384())
  else:
    raise newException(UnsupportedAlgorithm, $algorithm & " isn't supported")

# Verify that the token is not tampered with
proc verifySignature*(
    data: string, signature: seq[byte], secret: string, alg: SignatureAlgorithm
): bool =
  case alg
  of HS256, HS384, HS512:
    let dataSignature = signString(data, secret, alg)
    result = dataSignature == signature
  of RS256:
    result = crypto.bearVerifyRSPem(
      data, secret, signature, addr sha256Vtable, HASH_OID_SHA256, sha256SIZE
    )
  of RS384:
    result = crypto.bearVerifyRSPem(
      data, secret, signature, addr sha384Vtable, HASH_OID_SHA384, sha384SIZE
    )
  of RS512:
    result = crypto.bearVerifyRSPem(
      data, secret, signature, addr sha512Vtable, HASH_OID_SHA512, sha512SIZE
    )
  of ES256:
    result =
      crypto.bearVerifyECPem(data, secret, signature, addr sha256Vtable, sha256SIZE)
  of ES384:
    result =
      crypto.bearVerifyECPem(data, secret, signature, addr sha384Vtable, sha384SIZE)
  of ES512:
    result =
      crypto.bearVerifyECPem(data, secret, signature, addr sha512Vtable, sha512SIZE)
  else:
    assert(false, "Not implemented")

proc sign*(token: var JWT, secret: string) =
  assert token.signature.len == 0
  token.signature = signString(token.parsed, secret, token.header.alg)

# Verify a token typically an incoming request
proc verify*(token: JWT, secret: string, alg: SignatureAlgorithm): bool =
  token.header.alg == alg and verifySignature(
    token.loaded, token.signature, secret, alg
  )

proc toString*(token: JWT): string =
  token.header.toBase64 & "." & token.claims.toBase64 & "." & token.signatureToB64

proc toFlattenedJson*(token: JWT, unprotectedHeader: bool = false): JsonNode =
  # Converts JWT to flattened JSON format
  # https://datatracker.ietf.org/doc/html/rfc7515#section-7.2.2

  if not unprotectedHeader:
    return
      %*{
        "payload": token.claims.toBase64,
        "protected": token.header.toBase64,
        "signature": token.signatureToB64,
      }

  # protected field is the base64url of "typ" and "alg"
  let protected = %*{"typ": token.header["typ"], "alg": token.header["alg"]}

  # (unprotected) header field contains all other header keys and not on base64url
  var header = %*{}
  for key in token.header.keys:
    if not protected.hasKey(key):
      header[key] = token.header[key]
  return
    %*{
      "payload": token.claims.toBase64,
      "protected": protected.toBase64,
      "header": header,
      "signature": token.signatureToB64,
    }

proc `$`*(token: JWT): string =
  token.toString

proc `%`*(token: JWT): JsonNode =
  let s = $token
  %s

proc verifyTimeClaims*(token: JWT) =
  let now = getTime()
  if token.claims.hasKey("nbf"):
    let nbf = token.claims["nbf"].getClaimTime
    if now < nbf:
      raise newException(InvalidToken, "Token cant be used yet")

  if token.claims.hasKey("exp"):
    let exp = token.claims["exp"].getClaimTime
    if now > exp:
      raise newException(InvalidToken, "Token is expired")

  # Verify token nbf exp
