import { account, request_by_kid } from "./newAccount.mjs"

//updates contact
const PAYLOAD = {contact:["mailto:example@gmail.com"]}

console.log((await request_by_kid(account.location, PAYLOAD)).body);
debugger