JWT Implementation for Nim [![Build Status](https://github.com/yglukhov/nim-jwt/workflows/CI/badge.svg?branch=master)](https://github.com/yglukhov/nim-jwt/actions?query=branch%3Amaster)
===============================

This is a implementation of JSON Web Tokens for Nim, it allows for the following operations to be performed:

`proc toJWT*(node: JsonNode): JWT` - parse a JSON object representing a JWT token to create a JWT token object.

`proc toJWT*(s: string): JWT` - parse a base64 string to decode it to a JWT token object

`sign*(token: var JWT, secret: string)` - sign a token. Creates a `signature` property on the given token and assigns the signature to it.

`proc verify*(token: JWT, secret: string, alg: SignatureAlgorithm): bool` - verify a token (typically on your incoming requests)

`proc $*(token: JWT): string` - creates a b64url string from the token

## Installation
After installing nim's package manager `nimble` execute this:
`nimble install jwt`

## Examples

An example to demonstrate use with a userId

```nim
import jwt, times, json, tables

var secret = "secret"

proc sign(userId: string): string =
  var token = toJWT(%*{
    "header": {
      "alg": "HS256",
      "typ": "JWT"
    },
    "claims": {
      "userId": userId,
      "exp": (getTime() + 1.days).toUnix()
    }
  })

  token.sign(secret)

  result = $token

proc verify(token: string): bool =
  try:
    let jwtToken = token.toJWT()
    result = jwtToken.verify(secret, HS256)
  except InvalidToken:
    result = false

proc decode(token: string): string =
  let jwt = token.toJWT()
  result = $jwt.claims["userId"].node.str

```

Getting google api oauth2 token:
```nim
import jwt, json, times, httpclient, cgi

const email = "username@api-12345-12345.iam.gserviceaccount.com" # Acquired from google api console
const scope = "https://www.googleapis.com/auth/androidpublisher" # Define needed scope
const privateKey = """
-----BEGIN PRIVATE KEY-----
The key should be Acquired from google api console
-----END PRIVATE KEY-----
"""

var tok = initJWT(
  header = JOSEHeader(alg: RS256, typ: "JWT"),
  claims = toClaims(%*{
  "iss": email,
  "scope": scope,
  "aud": "https://www.googleapis.com/oauth2/v4/token",
  "exp": int(epochTime() + 60 * 60),
  "iat": int(epochTime())
}))

tok.sign(privateKey)

let postdata = "grant_type=" & encodeUrl("urn:ietf:params:oauth:grant-type:jwt-bearer") & "&assertion=" & $tok

proc request(url: string, body: string): string =
  var client = newHttpClient()
  client.headers = newHttpHeaders({ "Content-Length": $body.len, "Content-Type": "application/x-www-form-urlencoded" })
  result = client.postContent(url, body)
  client.close()

let resp = request("https://www.googleapis.com/oauth2/v4/token", postdata).parseJson()
echo "Access token is: ", resp["access_token"].str
```

Registering in [Let's Encrypt's](https://letsencrypt.org/) [ACME](https://www.rfc-editor.org/rfc/rfc8555) server
```nim
let key = "your_rsa_key_here"
let registerAccountPayload = %*{"termsOfServiceAgreed": true}
let resp = makeSignedAcmeRequest(getDirectory()["newAccount"].getStr, registerAccountPayload, key, needsJwk = true)
echo resp.body

proc makeSignedAcmeRequest(
    url: string, payload: JsonNode, accountKey: string, needsJwk: bool = false
): Response =
  let key = loadRsaKey(accountKey)
  var token = toJWT(
    %*{
      "header":
        getAcmeHeader(url, needsJwk, base64UrlEncode(key.n), base64UrlEncode(key.e)),
      "claims": payload,
    }
  )
  token.sign(accountKey)

  var client = newHttpClient()
  let body = token.toFlattennedJson
  echo body
  client.request(url, httpMethod = HttpPost, body = $body, headers = newHttpHeaders({"Content-Type": "application/jose+json"}))

proc getAcmeHeader(
    url: string, needsJwk: bool, n: string = "", e: string = ""
): JsonNode =
  var header = %*{"alg": Alg, "typ": "JWT", "nonce": getNewNonce(), "url": url}
  if needsJwk:
    header["jwk"] = %*{"kty": "RSA", "n": n, "e": e}
  else:
    header["kid"] = "some_kid"
  return header

proc getNewNonce(): string =
  let client = newHttpClient()
  let nonceURL = getDirectory()["newNonce"].getStr
  let resp = client.request(nonceURL, httpMethod = HttpGet)
  return resp.headers["replay-nonce"]

proc getDirectory(): JsonNode =
  let client = newHttpClient()
  let directory = parseJson(client.get(LetsEncryptURL & "/directory").body)
  return directory

```
