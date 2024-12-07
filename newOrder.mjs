import { createServer } from "http";
import { directory, jwk_public, request_by_kid } from "./newAccount.mjs";
import { generateKeyPairSync, hash, sign } from "crypto";
import { request } from "https";
import { ASN1, AlgorithmIdentifier, OID } from "./asn1.mjs";
import { writeFileSync } from "fs"

const DOMAIN_NAME = "example.org"

const CSR_SIGNATURE_ALGORITHM = AlgorithmIdentifier.ecdsaWithSHA384
// const CSR_SIGNATURE_ALGORITHM = AlgorithmIdentifier.sha256WithRSAEncryption

const CSR_SIGNATURE_KEY_PAIR = generateKeyPairSync("ec",{namedCurve: "secp384r1"}) //P-384
// const CSR_SIGNATURE_KEY_PAIR = generateKeyPairSync("ec",{namedCurve: "prime256v1"}) //P-256
// const CSR_SIGNATURE_KEY_PAIR = generateKeyPairSync("rsa",{modulusLength: 4096}) //4096 || 3072 || 2048

const PAYLOAD = {
    identifiers: [
        { "type": "dns", "value": DOMAIN_NAME }
        // { "type": "dns", "value": "example.org" },
        // { "type": "dns", "value": "www.example.org" },
    ]
}

const response_newOrder = await request_by_kid(directory.newOrder, PAYLOAD)
// const response_newOrder = {
//     "location": "https://acme-staging-v02.api.letsencrypt.org/acme/order/111111111/11111111111",
//     "body": {
//         "status": "pending",
//         "expires": "1111-11-11T11:11:11Z",
//         "identifiers": [
//             {
//                 "type": "dns",
//                 "value": "example.org"
//             }
//         ],
//         "authorizations": [
//             "https://acme-staging-v02.api.letsencrypt.org/acme/authz/111111111/11111111111"
//         ],
//         "finalize": "https://acme-staging-v02.api.letsencrypt.org/acme/finalize/111111111/11111111111"
//     }
// }

console.log(response_newOrder.location);

//simple GET request
function GET_request(url) {
    return new Promise(resolve=>{
        request(url,res=>{
            const toConcat = []
            res.on("data",chunk=>{
                toConcat.push(chunk)
            })
            res.on("end",()=>{
                resolve(JSON.parse(Buffer.concat(toConcat)))
            })
        }).end()
    })
}

function waitStopPending(state_not, response_order, timeout) {
    function poll(response_order, falsey) {
        if (response_order.status !== state_not) {
            return response_order
        } else {
            return falsey && new Promise(resolve=>{
                const interval = setInterval(async () => {
                    console.log(`poll for not "${state_not}" in waitStopPending`);
                    response_order = await GET_request(response_newOrder.location)
                    if (poll(response_order, false)) {
                        clearInterval(interval)
                        resolve(response_order)
                    }
                }, timeout);
            })
        }
    }
    return poll(response_order, true)
}


//may have already been completed
if (response_newOrder.body.status !== "pending") {
    await statusReady(response_newOrder.body)
} else {
    const response_auth = await GET_request(response_newOrder.body.authorizations[0])
    // const response_auth = {
    //     "identifier": {
    //         "type": "dns",
    //         "value": "example.org"
    //     },
    //     "status": "pending",
    //     "expires": "1111-11-11T11:11:11Z",
    //     "challenges": [
    //         {
    //             "type": "tls-alpn-01",
    //             "url": "https://acme-staging-v02.api.letsencrypt.org/acme/chall/111111111/11111111111/ZZZZZZ",
    //             "status": "pending",
    //             "token": "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
    //         },
    //         {
    //             "type": "dns-01",
    //             "url": "https://acme-staging-v02.api.letsencrypt.org/acme/chall/111111111/11111111111/ZZZZZZ",
    //             "status": "pending",
    //             "token": "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
    //         },
    //         {
    //             "type": "http-01",
    //             "url": "https://acme-staging-v02.api.letsencrypt.org/acme/chall/111111111/11111111111/ZZZZZZ",
    //             "status": "pending",
    //             "token": "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
    //         }
    //     ]
    // }

    const challenge = response_auth.challenges.find(v=>v.type==="http-01")

    // 1) ip36-109-133-66.letsencrypt.org - outbound1.letsencrypt.org - 66.133.109.36
    // 2) ec2-13-50-224-40.eu-north-1.compute.amazonaws.com - 13.50.224.40
    // 3) ec2-3-1-209-191.ap-southeast-1.compute.amazonaws.com - 3.1.209.191
    // 4) ec2-52-14-238-252.us-east-2.compute.amazonaws.com - 52.14.238.252
    // 5) ec2-54-202-56-162.us-west-2.compute.amazonaws.com - 54.202.56.162
    let count = 0
    let singleInstance
    const server = createServer((req,res)=>{
        if (req.url === `/.well-known/acme-challenge/${challenge.token}`) {
            req.on("end",async ()=>{
                ++count
                console.log(count, req.socket.remoteAddress);

                if (singleInstance) {
                    return
                }
                singleInstance = true
                const response_order = await waitStopPending("pending", response_newOrder.body, 1000)
                server.close()

                if (response_order.status === "ready") {
                    await statusReady(response_order)
                    return
                } else {
                    console.log("chall status is", response_order.status);
                    console.log(response_order);
                }
            })
            return res.end(`${challenge.token}.${hash("SHA256",JSON.stringify(jwk_public),"base64url")}`)
        }
    }).listen(80)

    await request_by_kid(challenge.url, {})
}

async function statusReady(response_order) {

    if (response_order.status === "valid") {
        await statusValid(response_order)
        return
    }

    if (response_order.status !== "ready") {
        console.log("status is", response_order.status);
        console.log(response_order);
        return
    }

    const subjectPublicKeyInfo = CSR_SIGNATURE_KEY_PAIR.publicKey.export({format: "der", type: "spki"})

    const certificationRequestInfo = ASN1.stringify({
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
            //   {
            //     type: "array",
            //     tag: 49,
            //     arr: [
            //       {
            //         type: "array",
            //         tag: 48,
            //         arr: [
            //           {
            //             type: "OBJECT IDENTIFIER",
            //             tag: 6,
            //             value: "2.5.4.6",
            //           },
            //           {
            //             type: "string",
            //             tag: 19,
            //             value: "XX",
            //           },
            //         ],
            //       },
            //     ],
            //   },
            //   {
            //     type: "array",
            //     tag: 49,
            //     arr: [
            //       {
            //         type: "array",
            //         tag: 48,
            //         arr: [
            //           {
            //             type: "OBJECT IDENTIFIER",
            //             tag: 6,
            //             value: "2.5.4.8",
            //           },
            //           {
            //             type: "string",
            //             tag: 12,
            //             value: "StateName",
            //           },
            //         ],
            //       },
            //     ],
            //   },
            //   {
            //     type: "array",
            //     tag: 49,
            //     arr: [
            //       {
            //         type: "array",
            //         tag: 48,
            //         arr: [
            //           {
            //             type: "OBJECT IDENTIFIER",
            //             tag: 6,
            //             value: "2.5.4.7",
            //           },
            //           {
            //             type: "string",
            //             tag: 12,
            //             value: "CityName",
            //           },
            //         ],
            //       },
            //     ],
            //   },
            //   {
            //     type: "array",
            //     tag: 49,
            //     arr: [
            //       {
            //         type: "array",
            //         tag: 48,
            //         arr: [
            //           {
            //             type: "OBJECT IDENTIFIER",
            //             tag: 6,
            //             value: "2.5.4.10",
            //           },
            //           {
            //             type: "string",
            //             tag: 12,
            //             value: "CompanyName",
            //           },
            //         ],
            //       },
            //     ],
            //   },
            //   {
            //     type: "array",
            //     tag: 49,
            //     arr: [
            //       {
            //         type: "array",
            //         tag: 48,
            //         arr: [
            //           {
            //             type: "OBJECT IDENTIFIER",
            //             tag: 6,
            //             value: "2.5.4.11",
            //           },
            //           {
            //             type: "string",
            //             tag: 12,
            //             value: "CompanySectionName",
            //           },
            //         ],
            //       },
            //     ],
            //   },
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
                        value: DOMAIN_NAME,
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
            tag: 160,
            arr: [
              {
                type: "array",
                tag: 48,
                arr: [
                  {
                    type: "OBJECT IDENTIFIER",
                    tag: 6,
                    value: OID.extensionRequest,
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
                                        type: "string",
                                        tag: 130,
                                        value: DOMAIN_NAME,
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
                                value: OID.extKeyUsage,
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
                                        type: "OBJECT IDENTIFIER",
                                        tag: 6,
                                        value: OID.serverAuth,
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

    const response_finalize = await request_by_kid(response_newOrder.body.finalize,{csr:certificationRequest.toString("base64url")})

    response_order = await waitStopPending("processing", response_finalize.body, 1000)

    if (response_order.status === "valid") {
        writeFileSync(`${DOMAIN_NAME}-key.pem`,CSR_SIGNATURE_KEY_PAIR.privateKey.export({format: "pem", type: "pkcs8"}))
        await statusValid(response_order)
        return
    } else {
        console.log("finalize status is", response_order.status);
        console.log(response_order);
    }
}

async function statusValid(response_order) {
    const PEM_chain = await new Promise(resolve=>{
        request(response_order.certificate,{
            headers: {
                "Content-Type": "application/pem-certificate-chain",
            }
        },res=>{
            const toConcat = []
            res.on("data",chunk=>{
                toConcat.push(chunk)
            })
            res.on("end",()=>{
                resolve(Buffer.concat(toConcat))
            })
        }).end()
    })
    writeFileSync(`${DOMAIN_NAME}-chain.pem`,PEM_chain)
}