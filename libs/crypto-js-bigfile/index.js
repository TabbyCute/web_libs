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
    
     /**
        @param {Uint8Array}
        @return {Uint8Array}
    */
    ///加密字节
    encByteAES(plainText){
        var wordArray = this.Uint8ToW(plainText);   // Uint8Array->WordArray
        let options = {iv:this.iv,mode:this.mode,padding:this.padding}
        const res = CryptoJS.AES.encrypt(wordArray, this.key,options).ciphertext
        return this.WToUint8(res)                   // WordArray->Uint8Array
    }
     /**
        @param {Uint8Array}
        @return {Uint8Array}
    */
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

}

class TBFileRules {
    static checkHeadSign=["abcdabcdabcdabc","abcdabcdabcdabcd"]                     ///解密时使用。是否符合解密文件。
    static headSign={sign:"abcdabcdabcdabcd",headLen:1024/2}                        ///加密时使用。标记为加密文件。对象编译过后的字节长度不能超过50
    static appKey="tabby"                                                           ///appkey 
    static encDataLen=1024*10;                                                      ///加密的长度，文件小于这个长度全加密 默认只加密10kb
    /**
        @param {string} -sgin:app签名
        @param {Number} -headLen:文件头的总长度
        @param {Number} -fileLen:文件的原长
        @param {Number} -fileEncLen:文件加密后总体的长度（不含头）
        @param {Number} -fileDataLen:加密段加密前的长度
        @param {Number} -fileDataEncLen:加密段加密后的长度
        @param {Number} -fileEncStart:加密后加密段开始的位置（不含头）
        @param {string} -ext:预留拓展字段
   */
    static generateHeaderByte(opt={}){
        var {fileLen,fileEncLen,fileDataLen,fileDataEncLen,fileEncStart,ext}=opt;
        let header={}
        header.sgin=TBFileRules.appKey;                     ///32 位app签名
        header.headLenSign=50;                              ///加密标识的长度
        header.headLen=TBFileRules.headSign.headLen;        ///文件头的总长度
        header.fileLen=fileLen;                             ///文件的原长
        header.fileEncLen=fileEncLen;                       ///文件加密后总体的长度（不含头）
        header.fileDataLen=fileDataLen;                     ///加密段加密前的长度
        header.fileDataEncLen=fileDataEncLen;               ///加密段加密后的长度
        header.fileEncStart=fileEncStart;                   ///加密后加密段开始的位置（不含头）
        header.ext=ext;                                     ///预留拓展字段
        // console.log(header)
        return TBFileRules.strToByte(JSON.stringify(header))
    }


    /**
        检查是否为加密文件
        @param {Uint8Array} -source:源文件
    */
    static checkIsEncFile(source){
        try{
            var headSign=JSON.parse(TBFileRules.byteToStr(TBFileRules.unshif0(source.slice(0,50))))
            if(TBFileRules.checkHeadSign.indexOf(headSign.sign)>-1)return headSign 
            return false
        }catch(e){
            console.log(e)
            return false
        }
    }
    

    /**
        加密文件
        @param {CryptoJSTB} -cjstb:CryptoJSTB 实例
        @param {Uint8Array} -source:源文件
        @param {String}     -ext:拓展
    */
    static encData(opt={}){
        return new Promise((resolve,reject)=>{
            var {cjstb,source,ext}=opt

            source=Array.from(source)
            if(!ext)ext=""

            var encDataU8=[],                               //加密前的加密段
                fileEnd=TBFileRules.encDataLen,             //加密结束的位置
                encDataSourceU8=[],                         //加密后的加密段
                sourceOtherData=[],                         //未加密的部分 
                sourceEecData=[];                           //未加密的部分
            

            if(fileEnd>source.length)fileEnd=source.length
            else sourceOtherData=source.slice(fileEnd)

            encDataU8=source.slice(0,fileEnd)
            encDataSourceU8=cjstb.encByteAES(encDataU8)
            sourceEecData=[...encDataSourceU8,...sourceOtherData]

            var headerParams = TBFileRules.generateHeaderByte({
                fileLen:source.length,
                fileEncLen:sourceEecData.length,
                fileDataLen:encDataU8.length,
                fileDataEncLen:encDataSourceU8.length,
                ext
            })
            var headerSign = TBFileRules.strToByte(JSON.stringify(TBFileRules.headSign))

            if(headerSign.length<=50){
                let ent=[]
                for(let i=0;i<50-headerSign.length;i++){ent.push(0)}
                headerSign=[...headerSign,...ent]
            }else{
                reject({code:0,msg:"headerSign.length  too long 50"})
            }
            var head=[...headerSign,...headerParams]
            
            if(head.length<TBFileRules.headSign.headLen){
                let ent=[]
                for(let i=0;i<TBFileRules.headSign.headLen-head.length;i++){ent.push(0)}
                head=[...head,...ent]
            }else{
                reject({code:0,msg:"File head too long"})
            }

            resolve({code:1,data:new Uint8Array([...head,...sourceEecData])})
        })

    }
    
    /**
        解密密文件
        @param {CryptoJSTB} -cjstb:CryptoJSTB 实例
        @param {Uint8Array} -source:源文件
    */
    static decData(opt={}){
        return new Promise((resolve,reject)=>{
            var {source,cjstb}=opt
            source=Array.from(source)
            var headSign=TBFileRules.checkIsEncFile(source)
            if(!headSign){
                reject({code:0,msg:"Failed to parse file"})
                return
            }
            var headParamsByte = source.slice(50,headSign.headLen)
            var headParamsByteUnfit0 = TBFileRules.unshif0(headParamsByte)
            var headParams = JSON.parse(TBFileRules.byteToStr(headParamsByteUnfit0))
            var encData=source.slice(headSign.headLen,headSign.headLen + headParams.fileDataEncLen)
            var otherData=source.slice(headSign.headLen + headParams.fileDataEncLen)
            var decData=cjstb.decByteAES(encData)
            resolve({
                code:1,
                params:headParams,
                data:new Uint8Array([...decData,...otherData])
            })
        })
    }
    

    /**
        文件转u8
        @param {file} 
        @return {Promise<Uint8Array>}
    */
    static fileToUint8(file){
        return new Promise((resolve,reject)=>{
            var reader = new FileReader();
            reader.onload = function (e) {resolve(new Uint8Array(e.target.result))}
            reader.readAsArrayBuffer(file);
        })
    }

    static saveFile(uint8List,fileName){
        var blob=new Blob([uint8List]);
        const link = document.createElement('a');
        link.href = window.URL.createObjectURL(blob);
        link.download = fileName;
        link.click();
        window.URL.revokeObjectURL(link.href);
    }


    ///去除字节最后的0
    static unshif0(list){
        var data=[...list]
        for(let i=0;i<list.length;i++){
            if(data[data.length-1])return data
            else data.pop()
        }
    }

    static strToByte(str) {
        var bytes = new Array();
        var len, c;
        len = str.length;
        for (var i = 0; i < len; i++) {
            c = str.charCodeAt(i);
            if (c >= 0x010000 && c <= 0x10FFFF) {
                bytes.push(((c >> 18) & 0x07) | 0xF0);
                bytes.push(((c >> 12) & 0x3F) | 0x80);
                bytes.push(((c >> 6) & 0x3F) | 0x80);
                bytes.push((c & 0x3F) | 0x80);
            } else if (c >= 0x000800 && c <= 0x00FFFF) {
                bytes.push(((c >> 12) & 0x0F) | 0xE0);
                bytes.push(((c >> 6) & 0x3F) | 0x80);
                bytes.push((c & 0x3F) | 0x80);
            } else if (c >= 0x000080 && c <= 0x0007FF) {
                bytes.push(((c >> 6) & 0x1F) | 0xC0);
                bytes.push((c & 0x3F) | 0x80);
            } else {
                bytes.push(c & 0xFF);
            }
        }
        return bytes;
    }

    static byteToStr(utf8Bytes){
        var unicodeStr ="";
        for (var pos = 0; pos < utf8Bytes.length;){
            var flag= utf8Bytes[pos];
            var unicode = 0 ;
            if ((flag >>>7) === 0 ) {
                unicodeStr+= String.fromCharCode(utf8Bytes[pos]);
                pos += 1;

            } else if ((flag &0xFC) === 0xFC ){
                unicode = (utf8Bytes[pos] & 0x3) << 30;
                unicode |= (utf8Bytes[pos+1] & 0x3F) << 24;
                unicode |= (utf8Bytes[pos+2] & 0x3F) << 18;
                unicode |= (utf8Bytes[pos+3] & 0x3F) << 12;
                unicode |= (utf8Bytes[pos+4] & 0x3F) << 6;
                unicode |= (utf8Bytes[pos+5] & 0x3F);
                unicodeStr+= String.fromCharCode(unicode) ;
                pos += 6;

            }else if ((flag &0xF8) === 0xF8 ){
                unicode = (utf8Bytes[pos] & 0x7) << 24;
                unicode |= (utf8Bytes[pos+1] & 0x3F) << 18;
                unicode |= (utf8Bytes[pos+2] & 0x3F) << 12;
                unicode |= (utf8Bytes[pos+3] & 0x3F) << 6;
                unicode |= (utf8Bytes[pos+4] & 0x3F);
                unicodeStr+= String.fromCharCode(unicode) ;
                pos += 5;

            } else if ((flag &0xF0) === 0xF0 ){
                unicode = (utf8Bytes[pos] & 0xF) << 18;
                unicode |= (utf8Bytes[pos+1] & 0x3F) << 12;
                unicode |= (utf8Bytes[pos+2] & 0x3F) << 6;
                unicode |= (utf8Bytes[pos+3] & 0x3F);
                unicodeStr+= String.fromCharCode(unicode) ;
                pos += 4;

            } else if ((flag &0xE0) === 0xE0 ){
                unicode = (utf8Bytes[pos] & 0x1F) << 12;;
                unicode |= (utf8Bytes[pos+1] & 0x3F) << 6;
                unicode |= (utf8Bytes[pos+2] & 0x3F);
                unicodeStr+= String.fromCharCode(unicode) ;
                pos += 3;

            } else if ((flag &0xC0) === 0xC0 ){ //110
                unicode = (utf8Bytes[pos] & 0x3F) << 6;
                unicode |= (utf8Bytes[pos+1] & 0x3F);
                unicodeStr+= String.fromCharCode(unicode) ;
                pos += 2;

            } else{
                unicodeStr+= String.fromCharCode(utf8Bytes[pos]);
                pos += 1;
            }
        }
        return unicodeStr;
    }
}