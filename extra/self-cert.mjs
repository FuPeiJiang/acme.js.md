import { generateKeyPairSync, hash, randomBytes, sign } from "crypto"
import { ASN1, AlgorithmIdentifier, OID } from "../asn1.mjs"
import { writeFileSync } from "fs"

const COMMON_NAME = "local.local.local"
const IP = "192.168.3.21"

const NOT_AFTER = (d=>(d.setUTCDate(d.getUTCDate()+800),d))(new Date())

// const SIGNATURE_ALGORITHM = AlgorithmIdentifier.ecdsaWithSHA384
const SIGNATURE_ALGORITHM = AlgorithmIdentifier.sha256WithRSAEncryption

// const SIGNATURE_KEY_PAIR = generateKeyPairSync("ec",{namedCurve: "secp384r1"}) //P-384
// const SIGNATURE_KEY_PAIR = generateKeyPairSync("ec",{namedCurve: "prime256v1"}) //P-256
const SIGNATURE_KEY_PAIR = generateKeyPairSync("rsa",{modulusLength: 4096}) //4096 || 3072 || 2048

writeFileSync(`${IP}-key.pem`,SIGNATURE_KEY_PAIR.privateKey.export({format: "pem", type: "pkcs8"}))

const subjectPublicKeyInfo = SIGNATURE_KEY_PAIR.publicKey.export({format: "der", type: "spki"})

const keyIdentifier = hash("SHA1",ASN1.stringify(ASN1.parse(subjectPublicKeyInfo).arr[1].arr[0]),"buffer")

const tbsCertificate = ASN1.stringify({
    type: "array",
    tag: 48,
    arr: [
      {
        type: "array",
        tag: 160,
        arr: [
          {
            type: "INTEGER",
            tag: 2,
            value: 2n,
          },
        ],
      },
      {
        type: "INTEGER",
        tag: 2,
        value: BigInt(`0x${(b=>(b[0]&=0x7F,b))(randomBytes(20)).toString("hex")}`),
      },
      {
        type: "array",
        tag: 48,
        arr: [
          {
            type: "OBJECT IDENTIFIER",
            tag: 6,
            value: SIGNATURE_ALGORITHM.OID,
          },
        ],
      },
      {
        type: "array",
        tag: 48,
        arr: [
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
                    value: OID.commonName,
                  },
                  {
                    type: "string",
                    tag: 12,
                    value: COMMON_NAME,
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
            type: "UTCTime",
            tag: 23,
            value: new Date(),
          },
          {
            type: "UTCTime",
            tag: 23,
            value: NOT_AFTER,
          },
        ],
      },
      {
        type: "array",
        tag: 48,
        arr: [
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
                    value: OID.commonName,
                  },
                  {
                    type: "string",
                    tag: 12,
                    value: COMMON_NAME,
                  },
                ],
              },
            ],
          },
        ],
      },
      {
        type: "ASN1",
        value: subjectPublicKeyInfo,
      },
      {
        type: "array",
        tag: 163,
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
                    value: OID.subjectKeyIdentifier,
                  },
                  {
                    type: "array",
                    tag: 4,
                    arr: [
                      {
                        type: "buffer",
                        tag: 4,
                        value: keyIdentifier,
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
                    value: OID.authorityKeyIdentifier,
                  },
                  {
                    type: "array",
                    tag: 4,
                    arr: [
                      {
                        type: "array",
                        tag: 48,
                        arr: [
                          {
                            type: "buffer",
                            tag: 128,
                            value: keyIdentifier,
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
                    value: OID.basicConstraints,
                  },
                  {
                    type: "BOOLEAN",
                    tag: 1,
                    value: true,
                  },
                  {
                    type: "array",
                    tag: 4,
                    arr: [
                      {
                        type: "array",
                        tag: 48,
                        arr: [
                          {
                            type: "BOOLEAN",
                            tag: 1,
                            value: true,
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
                    value: OID.subjectAltName,
                  },
                  {
                    type: "array",
                    tag: 4,
                    arr: [
                      {
                        type: "array",
                        tag: 48,
                        arr: [
                          {
                            type: "buffer",
                            tag: 135,
                            value: Buffer.from(IP.split(".")),
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
const certificate = ASN1.stringify({
    type: "array",
    tag: 48,
    arr: [
      {
        type: "ASN1",
        value: tbsCertificate,
      },
      {
        type: "array",
        tag: 48,
        arr: [
          {
            type: "OBJECT IDENTIFIER",
            tag: 6,
            value: SIGNATURE_ALGORITHM.OID,
          },
        ],
      },
      {
        type: "buffer",
        tag: 3,
        value: sign(SIGNATURE_ALGORITHM.digest,tbsCertificate,SIGNATURE_KEY_PAIR.privateKey),
        unusedBits: 0,
      },
    ],
  })
writeFileSync(`${IP}-cert.pem`,`-----BEGIN CERTIFICATE-----\n${certificate.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`)

debugger
