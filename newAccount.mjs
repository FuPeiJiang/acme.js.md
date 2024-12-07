import { createPrivateKey, createPublicKey, generateKeyPairSync, sign } from "crypto"
import { existsSync, readFileSync, writeFileSync } from "fs"
import { request } from "https"
import { fileURLToPath } from "url"

const ACME_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"
// const ACME_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"

const PAYLOAD = {contact:["mailto:example@gmail.com"],termsOfServiceAgreed:true}
// const PAYLOAD = {onlyReturnExisting:true}

const PRIVATE_KEY_PATH="privkey.json"

if (!existsSync(PRIVATE_KEY_PATH)) {
    const pair = generateKeyPairSync("ec",{namedCurve: "secp384r1"}) //P-384
    // const pair = generateKeyPairSync("ec",{namedCurve: "prime256v1"}) //P-256
    // const pair = generateKeyPairSync("rsa",{modulusLength: 4096}) //4096 || 3072 || 2048

    writeFileSync(PRIVATE_KEY_PATH,JSON.stringify(pair.privateKey.export({format: "jwk"})))
    // writeFileSync(PRIVATE_KEY_PATH,JSON.stringify(pair.privateKey.export({format: "pem", type: "pkcs8"})))
}

export const PRIVATE_KEY = createPrivateKey({format:"jwk",key:JSON.parse(readFileSync(PRIVATE_KEY_PATH))})
// export const PRIVATE_KEY = createPrivateKey({format:"pem",key:readFileSync(PRIVATE_KEY_PATH)})

export const ALG_JWS = {signing: "ES384", digest: "SHA384"}
// export const ALG_JWS = {signing: "RS256", digest: "SHA256"}

export const directory = await new Promise(resolve=>{
    request(ACME_DIRECTORY,res=>{
        const toConcat=[]
        res.on("data",chunk=>{
            toConcat.push(chunk)
        })
        res.on("end",()=>{
            resolve(JSON.parse(Buffer.concat(toConcat)))
        })
    }).end()
})

let saved_nounce
export function newNounce() {
    return new Promise(resolve=>{
        request(directory.newNonce,{
            method:"HEAD"
        },res=>{
            resolve(res.headers["replay-nonce"])
            res.destroy() //needed idk why
        }).end()
    })
}


export function base64url(obj) {
    return Buffer.from(JSON.stringify(obj)).toString("base64url")
}

export function sign_obj(obj) {
    obj.signature = sign(ALG_JWS.digest, `${obj.protected}.${obj.payload}`, {key:PRIVATE_KEY,dsaEncoding:'ieee-p1363'}).toString("base64url")
}

function isObj(value) {
    return typeof value === "object" && !Array.isArray(value)
}
function sortObj(unordered) {
    return Object.keys(unordered).sort().reduce((obj, key) => {
        const value = unordered[key]
        obj[key] = isObj(value) ? sortObj(value) : value
        return obj
    }, {});
}

export const jwk_public = sortObj(createPublicKey({key:PRIVATE_KEY}).export({format: "jwk"}))

async function newAccount(payload) {
    return await jose_request(directory.newAccount, payload, {
        "jwk": jwk_public,
    })
}

export async function request_by_kid(url, payload) {
    return await jose_request(url, payload, {
        "kid": account.location,
    })
}

async function jose_request(url, payload, jwk_or_kid) {
    const obj = {
        protected: base64url({
            "alg": ALG_JWS.signing,
            "jwk": jwk_or_kid.jwk, //JSON.stringify deletes undefined
            "kid": jwk_or_kid.kid, //JSON.stringify deletes undefined
            "nonce": saved_nounce || await newNounce(),
            "url": url,
        }),
        payload: base64url(payload),
    }
    sign_obj(obj)
    return new Promise(resolve=>{
        request(url,{
            method:"POST",
            headers: {
                "content-type": "application/jose+json",
            }
        },res=>{
            saved_nounce = res.headers["replay-nonce"]

            const toConcat = []
            res.on("data",chunk=>{
                toConcat.push(chunk)
            })
            res.on("end",()=>{
                resolve({location:res.headers.location,body:JSON.parse(Buffer.concat(toConcat))})
            })
        }).end(JSON.stringify(obj))
    })
}

//__name__ == '__main__'
const isMain = fileURLToPath(import.meta.url) === process.argv[1]
// export const account = await newAccount(isMain ? PAYLOAD : {onlyReturnExisting:true})
export const account = await newAccount(PAYLOAD)
if (isMain) {
    console.log(account);
}