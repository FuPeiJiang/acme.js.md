export const ASN1 = {
    parse(buf) {
        let i = 0

        function getLength(end) {
            // The encoding of length can take two forms: short or long. The short form is a single byte, between 0 and 127.
            if (buf[i] & 0x80) {
                //long
                // Bits 7-1 of the first byte indicate how many more bytes are in the length field itself.
                const lengthLength = buf[i] & 0x7f; ++i
                const lengthEnd = i + lengthLength
                if (lengthEnd > end) {
                    return -1
                }
                let length = 0
                for (; i < lengthEnd; ++i) {
                    length = length << 8 | buf[i]
                }
                return length
            } else {
                //short
                const length = buf[i]; ++i
                return length
            }
        }
        function bufferToBigInt(buf) {
            const num = BigInt(`0x${buf.toString("hex")}`)
            return buf[0] & 0x80 ? num - (1n << BigInt(buf.length << 3)) : num
            //2's complement:
            //MSB(leftmost bit) is supposed to be negative
            //BigInt parses MSB as positive, the rest of bits are parsed correctly as positive
            //MSB - (MSB<<1) makes it negative
        }
        function getInteger(end,tag) {
            const int = bufferToBigInt(buf.subarray(i,end))
            i = end
            return {type:"INTEGER",tag,value:int}
        }
        function get_array(end, tag) {
            const iBak = i
            const arr = []
            while (i < end) {
                const got = get(end)
                if (got) {
                    arr.push(got)
                } else {
                    i = iBak
                    return
                }
            }
            return {type:"array", tag, arr}
        }
        function getObjectIdentifier(end,tag) {
            const arr = []
            function getComponent() {
                let component = 0
                --i; do {
                    ++i
                    component = component << 7 | (buf[i] & 0x7F)
                } while (buf[i] & 0x80)
                ++i;
                return component
            }

            //[0-39] -> 0.[0-39]
            //[40-79] -> 1.[0-39]
            //[80-...] -> 2.[0-...]
            const firstAndSecondComponent = getComponent()
            const firstComponent = firstAndSecondComponent < 40 ? 0 : (firstAndSecondComponent < 80 ? 1 : 2)
            arr.push(firstComponent,firstAndSecondComponent-(40*firstComponent))
            while (i < end) {
                arr.push(getComponent())
            }
            const OID = arr.join(".")
            return {type:"OBJECT IDENTIFIER",tag,value:OID}
        }
        function get_string(end,tag) {
            const str = buf.toString("utf8",i,end)
            i = end
            return {type:"string",tag,value:str}
        }
        function getBitsString(end,tag) {
            const unusedBits = buf[i]; ++i
            if (!unusedBits) {
                const got = get_array(end,tag)
                if (got) {
                    got.unusedBits = unusedBits
                    return got
                }
            }
            const sub_buf = buf.subarray(i,end)
            i = end
            return {type:"buffer",tag,unusedBits,value:sub_buf}
        }
        function getOctetString(end,tag) {
            const got = get_array(end,tag)
            if (got) {
                return got
            }
            const sub_buf = buf.subarray(i,end)
            if (sub_buf.every(v=>(v>=0x20 && v<=0x7E))) {
                return get_string(end,tag)
            }
            i = end
            return {type:"buffer",tag,value:sub_buf}
        }
        function get(end) {
            if (i + 2 >= end) {
                return
            }
            const tag = buf[i]; ++i;
            const length = getLength(end)
            if (length === -1) {
                return
            }
            const sub_end = i + length
            if (sub_end > end) {
                return
            }

            // Class, Bit 8, Bit 7
            // Context-specific, 1, 0
            if ((tag & 0xc0) === 0x80) {
                // _, Bit 6
                // Constructed, 1
                // Primitive, 0
                if (tag & 0x20) {
                    return get_array(sub_end,tag)
                } else {
                    return getOctetString(sub_end,tag)
                }
            }

            switch (tag) {
                case 0x30: case 0x31: return get_array(sub_end,tag)
                case 0x2: return getInteger(sub_end,tag)
                case 0x6: return getObjectIdentifier(sub_end,tag)
                case 0x13: case 0xc: return get_string(sub_end,tag)
                case 0x3: return getBitsString(sub_end,tag)
                case 0x4: return getOctetString(sub_end,tag)
                default: debugger
            }
        }
        return get(buf.length)
    },
    stringify(obj) {
        function bigIntToBuffer(int) {
            if (int < 0) {
                const hex = (int + (1n << BigInt(((int.toString(16).length + 1) & -2) << 2))).toString(16)
                return Buffer.from(hex,"hex")
            } else {
                const hex = int.toString(16)
                if (((hex.length & 1))) {
                    const buf = Buffer.allocUnsafe((hex.length >>> 1) + 1)
                    buf.write(hex.slice(1),1,"hex")
                    buf[0] = parseInt(hex[0],16)
                    return buf
                } else if (hex[0] < '8') {
                    return Buffer.from(hex,"hex")
                } else {
                    const buf = Buffer.allocUnsafe((hex.length >>> 1) + 1)
                    buf.write(hex,1,"hex")
                    buf[0] = 0
                    return buf
                }
            }
        }
        function objectIdentifierToBuffer(oid) {
            const buf = Buffer.allocUnsafe(oid.length) //buffer size will never be larger than string length
            const arr = oid.split(".").map(v=>Number(v))
            let i = buf.length - 1
            function write(int) {
                buf[i] = int & 0x7F; --i
                while ((int >>>= 7)) {
                    buf[i] = 0x80 | (int & 0x7F); --i
                }
            }
            for (let j = arr.length - 1; j >= 2; --j) {
                write(arr[j])
            }
            write(arr[0] * 40 + arr[1])
            return buf.subarray(i + 1)
        }
        function lengthToBuffer(length) {
            if (length <= 127) {
                return Buffer.from([length])
            } else {
                const hex = length.toString(16)
                if (((hex.length & 1))) {
                    const buf = Buffer.allocUnsafe((hex.length >>> 1) + 2)
                    buf.write(hex.slice(1),2,"hex")
                    buf[1] = parseInt(hex[0],16)
                    buf[0] = ((hex.length >>> 1) + 1) | 0x80
                    return buf
                } else {
                    const buf = Buffer.allocUnsafe((hex.length >>> 1) + 1)
                    buf.write(hex,1,"hex")
                    buf[0] = (hex.length >>> 1) | 0x80
                    return buf
                }
            }
        }
        function getPrimitive(obj,valueBuf) {
            const valueLength = valueBuf.length + (obj.hasOwnProperty("unusedBits") ? 1 : 0)
            const lengthBuf = lengthToBuffer(valueLength)
            const totalLength = 1 + lengthBuf.length + valueLength
            return {tag:obj.tag,lengthBuf,totalLength,valueBuf,...(obj.hasOwnProperty("unusedBits")) && {unusedBits:obj.unusedBits}}
        }
        //primitives: {tag,lengthBuf,totalLength,valueBuf,unusedBits?} (totalLength=1+lengthBuf.length+valueBuf.length)
        //arr: {tag,lengthBuf,totalLength,arr,unusedBits?} (totalLength=1+lengthBuf.length+sum_length(arr))
        function get_length_obj(obj) {
            switch (obj.type) {
                case "array":{
                    const arr = obj.arr.map(v=>get_length_obj(v))
                    const valueLength = arr.reduce((accum,v)=>accum+v.totalLength,0) + (obj.hasOwnProperty("unusedBits") ? 1 : 0)
                    const lengthBuf = lengthToBuffer(valueLength)
                    const totalLength = 1 + lengthBuf.length + valueLength
                    return {tag:obj.tag,lengthBuf,totalLength,arr,...(obj.hasOwnProperty("unusedBits")) && {unusedBits:obj.unusedBits}}
                }
                case "INTEGER":return getPrimitive(obj,bigIntToBuffer(obj.value))
                case "OBJECT IDENTIFIER": return getPrimitive(obj,objectIdentifierToBuffer(obj.value))
                case "string": return getPrimitive(obj,Buffer.from(obj.value))
                case "buffer": return getPrimitive(obj,obj.value)
                case "ASN1": return {asn1Buf:obj.value, totalLength:obj.value.length}
                default:debugger
            }
        }
        function get_buf(length_obj) {
            const buf = Buffer.allocUnsafe(length_obj.totalLength)
            let i = 0
            function write(length_obj) {
                if (length_obj.asn1Buf) {
                    buf.set(length_obj.asn1Buf, i); i+=length_obj.asn1Buf.length
                    return
                }
                buf[i] = length_obj.tag; ++i
                buf.set(length_obj.lengthBuf, i); i+=length_obj.lengthBuf.length
                if (length_obj.hasOwnProperty("unusedBits")) {
                    buf[i] = length_obj.unusedBits; ++i
                }
                if (length_obj.arr) {
                    length_obj.arr.forEach(v=>write(v))
                } else {
                    buf.set(length_obj.valueBuf, i); i+=length_obj.valueBuf.length
                }
            }
            write(length_obj)
            return buf
        }
        const length_obj = get_length_obj(obj)
        return get_buf(length_obj)
    },
}

export const AlgorithmIdentifier = {
    ecdsaWithSHA256: {OID:'1.2.840.10045.4.3.2', digest:"sha256"},
    ecdsaWithSHA384: {OID:'1.2.840.10045.4.3.3', digest:"sha384"},
    sha256WithRSAEncryption: {OID:'1.2.840.113549.1.1.11', digest:"sha256"},
}

export const OID = {
    commonName: "2.5.4.3",
    extensionRequest: "1.2.840.113549.1.9.14",
    subjectAltName: "2.5.29.17",
    extKeyUsage: "2.5.29.37",
    serverAuth: "1.3.6.1.5.5.7.3.1",
}