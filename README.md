configure CONSTANTS in `newAccount.mjs` and `newOrder.mjs`<br>
then run `newOrder.mjs`<br>

example output of `newOrder.mjs`:

```sh
https://acme-staging-v02.api.letsencrypt.org/acme/order/111111111/11111111111
1 ::ffff:66.133.109.36
2 ::ffff:13.53.137.103
3 ::ffff:54.169.254.92
(10) poll for not "pending" in waitStopPending
4 ::ffff:3.22.119.215
5 ::ffff:35.89.179.110
(11) poll for not "pending" in waitStopPending
(3) poll for not "processing" in waitStopPending
```

when this is done, you'll see output files in cwd:

`privkey.json`: account key<br>
`{{domain_name}}-chain.pem`: usable `cert` for `createServer()`<br>
`{{domain_name}}-key.pem`: usable `key` for `createServer()`<br>


CONSTANTS:<br>
switch `ACME_DIRECTORY` to not be staging, if you want valid certs<br>
a valid email should be in `PAYLOAD.contact`, or simply no email at all<br>

`DOMAIN_NAME` needs to be changed too<br>

___

"account" is defined by private key (no username)<br>
you can check account info by "creating an account" (onlyReturnExisting)<br>

key creation: create a pair, send public key to server, sign message using private key

| algorithm    | description |
| -------- | ------- |
| ~~HS256, HS384, HS512~~ | ~~HMAC using SHA-{256,384,512}~~                          |
| RS256, ~~RS384, RS512~~ | RSASSA-PKCS1-v1_5 using SHA-{256,~~384,512~~}             |
| ES256, ES384, ~~ES512~~ | ECDSA using P-{256,384,~~521~~} and SHA-{256,384,~~512~~} |

"alg" choices: https://www.iana.org/assignments/jose/jose.

letsencrypt supported "alg" choices: https://letsencrypt.org/docs/integration-guide/#supported-key-algorithms

| supported algorithm    |
| -------- |
| RS256 |
| ES256, ES384 |


> Let’s Encrypt accepts RSA keys that are 2048, 3072, or 4096 bits in length and P-256 or P-384 ECDSA keys. That’s true for both account keys and certificate keys.

(based on testing: `RS384`, `RS512` give error: "Parse error reading JWS")

___

since we don't store [account url],<br>
the whole code of newAccount.mjs is required for getting [account url]<br>

trying to use `jwk_public`:
```js
protected: base64url({
    "alg": ALG_JWS.signing,
    "jwk": jwk_public,
    "nonce": await newNounce(),
    "url": url,
}),
```
will give `'No Key ID in JWS header'`

for the rest of the endpoints, [account url] should be used instead:
```js
protected: base64url({
    "alg": ALG_JWS.signing,
    "kid": account.location,
    "nonce": await newNounce(),
    "url": url,
}),
```
___

trying to update `contact` would look like this

[AccountUpdate.mjs](./AccountUpdate.mjs)
```js
import { account, request_by_kid } from "./newAccount.mjs"

//updates contact
const PAYLOAD = {contact:["mailto:example@gmail.com"]}

console.log(await request_by_kid(account.location, PAYLOAD));
```

___

here is a glimpse of the intermediate representation used to build DER encoded ASN.1 for the Certificate Signing Request (CSR)
```js
const certificationRequest = ASN1.stringify({
  type: "array",
  tag: 48,
  arr: [
    {
      type: "ASN1",
      value: certificationRequestInfo,
    },
    {
      type: "array",
      tag: 48,
      arr: [
        {
          type: "OBJECT IDENTIFIER",
          tag: 6,
          value: CSR_SIGNATURE_ALGORITHM.OID,
        },
      ],
    },
    {
      type: "buffer",
      tag: 3,
      value: sign(CSR_SIGNATURE_ALGORITHM.digest,certificationRequestInfo,CSR_SIGNATURE_KEY_PAIR.privateKey),
      unusedBits: 0,
    },
  ],
})
```
found in newOrder.mjs