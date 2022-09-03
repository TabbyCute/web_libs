import CryptoJS from "./crypto-js/crypto-js"

class CryptoJSTB {

    iv=null

    key=null

    mode= null
    
    padding=null

    static fromJson(opt={}){
        var intance = new CryptoJSTB();
        let {iv,key,mode,padding} = opt
        intance.iv=iv;
        intance.key=key;
        intance.mode=mode||CryptoJS.mode.CBC;
        intance.padding=padding||CryptoJS.pad.Pkcs7;
        return intance
    }

    ///加密字符串
    encStrAES (plainText) {
        let options = {iv:this.iv,mode:this.mode,padding:this.padding}
        let words = CryptoJS.enc.Utf8.parse(plainText)
        let encrypted = CryptoJS.AES.encrypt(words,this.key,options)
        return CryptoJS.enc.Base64.stringify(encrypted.ciphertext)
    }

    ///解密字符串
    decStrAES (plainText) {
        let options = {iv:this.iv,mode:this.mode,padding:this.padding}
        ///加密的时候导出的base64，这里也用base64解析
        let base64 = CryptoJS.enc.Base64.parse(plainText)
        let src = CryptoJS.enc.Base64.stringify(base64)
        let decrypt = CryptoJS.AES.decrypt(src, this.key, options)
        let decryptedStr = decrypt.toString(CryptoJS.enc.Utf8)
        return decryptedStr.toString()
    }
    
    ///加密字节
    encByteAES(plainText){
        var wordArray = this.Uint8ToW(plainText);   // Uint8Array->WordArray
        let options = {iv:this.iv,mode:this.mode,padding:this.padding}
        const res = CryptoJS.AES.encrypt(wordArray, this.key,options).ciphertext
        return this.WToUint8(res)                   // WordArray->Uint8Array
    }
    
    ///解密字节
    decByteAES(plainText){
        var wordArray = this.Uint8ToW(plainText);   // Uint8Array->WordArray
        let options = {iv:this.iv,mode:this.mode,padding:this.padding}
        var content = CryptoJS.lib.CipherParams.create({ciphertext:wordArray})
        var res = CryptoJS.AES.decrypt(content, this.key,options)
        return this.WToUint8(res)                   // WordArray->Uint8Array
    }
    

    //类型转换
    //Uint8Array -> wordArray
    Uint8ToW(u8) {
        const len = u8.length;
        const words= [];
        for (let i = 0; i < len; i += 1) {
            words[i >>> 2] |= (u8[i] & 0xff) << (24 - (i % 4) * 8);
        }
        var res = CryptoJS.lib.WordArray.create(words, len);
        return res;
    }
    //wordArray -> Uint8Array
    WToUint8(wordArray){
        const { words } = wordArray;
        const { sigBytes } = wordArray;
        const u8 = new Uint8Array(sigBytes);
        for (let i = 0; i < sigBytes; i += 1) {
            const byte = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
            u8[i] = byte;
        }
        return u8;
    }

    ///文件转u8
    static fileToUint8(file){
        return new Promise((resolve,reject)=>{
            var reader = new FileReader();
            reader.onload = function (e) {resolve(new Uint8Array(e.target.result))}
            reader.readAsArrayBuffer(file);
        })
    }

    ///文件保存 
    static saveFile(uint8List,fileName){
        var blob=new Blob([uint8List]);
        const link = document.createElement('a');
        link.href = window.URL.createObjectURL(blob);
        link.download = fileName;
        link.click();
        window.URL.revokeObjectURL(link.href);
    }
}