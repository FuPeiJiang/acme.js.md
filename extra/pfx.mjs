import { createCipheriv, createHmac, hash, pbkdf2Sync, randomBytes } from "crypto";
import { ASN1, OID } from "../asn1.mjs";
import { readFileSync, writeFileSync } from "fs";

const PASSWORD = "abc" //empty pfx password is allowed
const CERT_PATH = "192.168.3.21-cert.pem"
const KEY_PATH = "192.168.3.21-key.pem"
const OUT_PFX_PATH = "192.168.3.21.pfx"

function PKCS12KDF(password, salt, iterations, hash_algorithm) {
  // H(H(H(... H(D||S||P))))
  // D is 0x3 repeated
  // S is salt repeated
  // P is password repeated

  const D = Buffer.alloc(64, 0x3);
  const S = Buffer.alloc(64, salt)
  const P = Buffer.alloc(64, password)

  let A = Buffer.concat([D, S, P])

  for (let i = iterations; i--;) {
      A = hash(hash_algorithm, A, "buffer")
  }
  return A
}

function UTF16_null_terminated(str) {
  const buf = Buffer.allocUnsafe((str.length + 1) << 1)
  buf.writeUint16LE(0,str.length << 1)
  buf.write(str,"utf16le")
  buf.swap16() //hopefully utf16be
  return buf
}

const macSalt = randomBytes(8)
const macKey = PKCS12KDF(UTF16_null_terminated(PASSWORD),macSalt,2048,"SHA256")

const cert_KDF_salt = randomBytes(16)
const cert_AES_key = pbkdf2Sync(PASSWORD,cert_KDF_salt,2048,32,"SHA256")
const cert_AES_iv = randomBytes(16)
const cert_cipher = createCipheriv("aes-256-cbc",cert_AES_key,cert_AES_iv)
const cert_unencrypted = Buffer.from(readFileSync(CERT_PATH).toString().replace(/-----.*?-----|\n/g,""),"base64")

const localKeyId = hash("SHA1",cert_unencrypted,"buffer")

const cert_SafeContents_unencrypted = ASN1.stringify({
  type: "array",
  tag: 48,
  arr: [
    {
      type: "array",
      tag: 48,
      arr: [
        {
          type: "OBJECT IDENTIFIER",
          tag: 6,
          value: OID.certBag,
        },
        {
          type: "array",
          tag: 160,
          arr: [
            {
              type: "array",
              tag: 48,
              arr: [
                {
                  type: "OBJECT IDENTIFIER",
                  tag: 6,
                  value: OID.x509Certificate,
                },
                {
                  type: "array",
                  tag: 160,
                  arr: [
                    {
                      type: "array",
                      tag: 4,
                      arr: [
                        {
                          type: "ASN1",
                          value: cert_unencrypted,
                        },
                      ],
                    },
                  ],
                },
              ],
            },
          ],
        },
        {
          type: "array",
          tag: 49,
          arr: [
            {
              type: "array",
              tag: 48,
              arr: [
                {
                  type: "OBJECT IDENTIFIER",
                  tag: 6,
                  value: OID.localKeyId,
                },
                {
                  type: "array",
                  tag: 49,
                  arr: [
                    {
                      type: "buffer",
                      tag: 4,
                      value: localKeyId,
                    },
                  ],
                },
              ],
            },
          ],
        },
      ],
    },
  ],
})

const cert_SafeContents_encrypted = Buffer.concat([cert_cipher.update(cert_SafeContents_unencrypted),cert_cipher.final()])

const key_KDF_salt = randomBytes(16)
const key_AES_key = pbkdf2Sync(PASSWORD,key_KDF_salt,2048,32,"SHA256")
const key_AES_iv = randomBytes(16)
const key_cipher = createCipheriv("aes-256-cbc",key_AES_key,key_AES_iv)
const key_unencrypted = Buffer.from(readFileSync(KEY_PATH).toString().replace(/-----.*?-----|\n/g,""),"base64")
const key_encrypted = Buffer.concat([key_cipher.update(key_unencrypted),key_cipher.final()])

const AuthenticatedSafe = ASN1.stringify({
  type: "array",
  tag: 48,
  arr: [
    {
      type: "array",
      tag: 48,
      arr: [
        {
          type: "OBJECT IDENTIFIER",
          tag: 6,
          value: OID.encryptedData,
        },
        {
          type: "array",
          tag: 160,
          arr: [
            {
              type: "array",
              tag: 48,
              arr: [
                {
                  type: "INTEGER",
                  tag: 2,
                  value: 0n,
                },
                {
                  type: "array",
                  tag: 48,
                  arr: [
                    {
                      type: "OBJECT IDENTIFIER",
                      tag: 6,
                      value: OID.data,
                    },
                    {
                      type: "array",
                      tag: 48,
                      arr: [
                        {
                          type: "OBJECT IDENTIFIER",
                          tag: 6,
                          value: OID.PBES2,
                        },
                        {
                          type: "array",
                          tag: 48,
                          arr: [
                            {
                              type: "array",
                              tag: 48,
                              arr: [
                                {
                                  type: "OBJECT IDENTIFIER",
                                  tag: 6,
                                  value: OID.PBKDF2,
                                },
                                {
                                  type: "array",
                                  tag: 48,
                                  arr: [
                                    {
                                      type: "buffer",
                                      tag: 4,
                                      value: cert_KDF_salt,
                                    },
                                    {
                                      type: "INTEGER",
                                      tag: 2,
                                      value: 2048n,
                                    },
                                    {
                                      type: "array",
                                      tag: 48,
                                      arr: [
                                        {
                                          type: "OBJECT IDENTIFIER",
                                          tag: 6,
                                          value: OID.hmacWithSHA256,
                                        },
                                      ],
                                    },
                                  ],
                                },
                              ],
                            },
                            {
                              type: "array",
                              tag: 48,
                              arr: [
                                {
                                  type: "OBJECT IDENTIFIER",
                                  tag: 6,
                                  value: OID.aes256_CBC,
                                },
                                {
                                  type: "buffer",
                                  tag: 4,
                                  value: cert_AES_iv,
                                },
                              ],
                            },
                          ],
                        },
                      ],
                    },
                    {
                      type: "buffer",
                      tag: 128,
                      value: cert_SafeContents_encrypted,
                    },
                  ],
                },
              ],
            },
          ],
        },
      ],
    },
    {
      type: "array",
      tag: 48,
      arr: [
        {
          type: "OBJECT IDENTIFIER",
          tag: 6,
          value: OID.data,
        },
        {
          type: "array",
          tag: 160,
          arr: [
            {
              type: "array",
              tag: 4,
              arr: [
                {
                  type: "array",
                  tag: 48,
                  arr: [
                    {
                      type: "array",
                      tag: 48,
                      arr: [
                        {
                          type: "OBJECT IDENTIFIER",
                          tag: 6,
                          value: OID.pkcs8ShroudedKeyBag,
                        },
                        {
                          type: "array",
                          tag: 160,
                          arr: [
                            {
                              type: "array",
                              tag: 48,
                              arr: [
                                {
                                  type: "array",
                                  tag: 48,
                                  arr: [
                                    {
                                      type: "OBJECT IDENTIFIER",
                                      tag: 6,
                                      value: OID.PBES2,
                                    },
                                    {
                                      type: "array",
                                      tag: 48,
                                      arr: [
                                        {
                                          type: "array",
                                          tag: 48,
                                          arr: [
                                            {
                                              type: "OBJECT IDENTIFIER",
                                              tag: 6,
                                              value: OID.PBKDF2,
                                            },
                                            {
                                              type: "array",
                                              tag: 48,
                                              arr: [
                                                {
                                                  type: "buffer",
                                                  tag: 4,
                                                  value: key_KDF_salt,
                                                },
                                                {
                                                  type: "INTEGER",
                                                  tag: 2,
                                                  value: 2048n,
                                                },
                                                {
                                                  type: "array",
                                                  tag: 48,
                                                  arr: [
                                                    {
                                                      type: "OBJECT IDENTIFIER",
                                                      tag: 6,
                                                      value: OID.hmacWithSHA256,
                                                    },
                                                  ],
                                                },
                                              ],
                                            },
                                          ],
                                        },
                                        {
                                          type: "array",
                                          tag: 48,
                                          arr: [
                                            {
                                              type: "OBJECT IDENTIFIER",
                                              tag: 6,
                                              value: OID.aes256_CBC,
                                            },
                                            {
                                              type: "buffer",
                                              tag: 4,
                                              value: key_AES_iv,
                                            },
                                          ],
                                        },
                                      ],
                                    },
                                  ],
                                },
                                {
                                  type: "buffer",
                                  tag: 4,
                                  value: key_encrypted,
                                },
                              ],
                            },
                          ],
                        },
                        {
                          type: "array",
                          tag: 49,
                          arr: [
                            {
                              type: "array",
                              tag: 48,
                              arr: [
                                {
                                  type: "OBJECT IDENTIFIER",
                                  tag: 6,
                                  value: OID.localKeyId,
                                },
                                {
                                  type: "array",
                                  tag: 49,
                                  arr: [
                                    {
                                      type: "buffer",
                                      tag: 4,
                                      value: localKeyId,
                                    },
                                  ],
                                },
                              ],
                            },
                          ],
                        },
                      ],
                    },
                  ],
                },
              ],
            },
          ],
        },
      ],
    },
  ],
})

const PFX = ASN1.stringify({
  type: "array",
  tag: 48,
  arr: [
    {
      type: "INTEGER",
      tag: 2,
      value: 3n,
    },
    {
      type: "array",
      tag: 48,
      arr: [
        {
          type: "OBJECT IDENTIFIER",
          tag: 6,
          value: OID.data,
        },
        {
          type: "array",
          tag: 160,
          arr: [
            {
              type: "buffer",
              tag: 4,
              value: AuthenticatedSafe,
            },
          ],
        },
      ],
    },
    {
      type: "array",
      tag: 48,
      arr: [
        {
          type: "array",
          tag: 48,
          arr: [
            {
              type: "array",
              tag: 48,
              arr: [
                {
                  type: "OBJECT IDENTIFIER",
                  tag: 6,
                  value: OID.sha256,
                },
              ],
            },
            {
              type: "buffer",
              tag: 4,
              value: createHmac("SHA256",macKey).update(AuthenticatedSafe).digest(),
            },
          ],
        },
        {
          type: "buffer",
          tag: 4,
          value: macSalt,
        },
        {
          type: "INTEGER",
          tag: 2,
          value: 2048n,
        },
      ],
    },
  ],
})

writeFileSync(OUT_PFX_PATH,PFX)

debugger