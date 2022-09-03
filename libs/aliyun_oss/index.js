import base64 from './scripts/base64.js' ; 
import CryptoJS from './scripts/crypto-js.js';

class Config {
    OSS={
        success_action_status:200,                                          //上传成功后的网络响应码
        OssAddress:`http://wh-fy.oss-cn-hangzhou.aliyuncs.com/`,   // OSS地址
        bucketSrc:"fy_talk_file/",                                             // 需要存入的oss路径
        AccessKeySecret:'ijVL6QvEbdIbAoe4xHBKma5wCeNNz9',               //
        OSSAccessKeyId:'LTAI5t7dF1GY84Xa6JW3wxUw',                     //
        timeout:87600,                                          //这个是上传文件时Policy和signature的有效时间小时
        conditions:[["content-length-range",0,1024*3000]],       //规则          //生成policy如果没有可能报400
    }
}

/**
    oss 绕开服务端客户端直传

    GetSignatureWithPolicy生成的对象有效时长由配置文件中的时间决定timeout

    如果oss没设置跨域可能会报错

    <input type="file" class="inp" multiple>
    <script type="module">
        import AliyunOSSRirect from "./aliyun_oss/index.js";
        var oss = new AliyunOSSRirect()

        document.querySelector(".inp").addEventListener("change", function (e) {
            var file = document.querySelector(".inp").files[0]
            console.log(file.name)
            oss.UploadFileForWeb(file).then(res=>{
                console.log(res)
            }).catch(e=>{
                console.log(e)
            })
        })
    </script>
    



    var oss = new AliyOss();
    uni.chooseImage({
        count:1,
        success: (chooseImageRes) => {
            const tempFilePaths = chooseImageRes.tempFilePaths;
            oss.UploadFileForUniapp(tempFilePaths[0]).then(res=>{
                console.log(res)
            }).catch(e=>{
                console.log(e)
            })
        }
    });

*/

class AliyunOSSRirect extends Config {
    constructor(){
        super()
    }
    /**
        生成policy(Base64格式)，用policy(Base64格式)生成signature
        @tip -conditions:必需要否则会报400!!!
        @return {Object} {signature ，policy}
    */
    GetSignatureWithPolicy(){
        var date = new Date();
        date.setHours(date.getHours() + this.OSS.timeout);
        var srcT = date.toISOString();

        var policyText = {"expiration": srcT,"conditions":this.OSS.conditions};
        var policy = base64.encode(JSON.stringify(policyText))

        var bytes = CryptoJS.HmacSHA1(policy,this.OSS.AccessKeySecret);
        var signature = CryptoJS.enc.Base64.stringify(bytes);

        return {signature,policy};
    }
    /**
        用生成默认的文件名称(可带oss路径)
        @param {string} -filePath:文件路径
        @param {<string>} -dir:需要存入的OSS路径(桶路径)
        @return {string} 
    */
    GeneraterDefaultFileName(filePath,dir=""){
        var fileArray = filePath.split(".")
        var fileType = fileArray[fileArray.length-1]
        return `${dir}${new Date().getTime()}${ Math.floor(Math.random() * 150)}.${fileType}`
    }
    
    /**
        @param {file}           -file:文件
        @param {<string>}       -dir:需要存入的OSS路径(桶路径)
        @param {<string>}       -fileKye:接受的字段
        @return {Promise} 
    */
    UploadFileForWeb(file,dir="",fileKye="file"){
        var key = this.GeneraterDefaultFileName(file.name,dir||this.OSS.bucketSrc)
        var {policy,signature} =this.GetSignatureWithPolicy()
        var {success_action_status,OSSAccessKeyId} =this.OSS
        var params={key,policy,signature,success_action_status,OSSAccessKeyId}
        var formData = new FormData()
        formData.append(fileKye,file)
        for(let key in params){formData.append(key,params[key])}
        return new Promise((resolve,reject)=>{
            fetch(this.OSS.OssAddress, {method:'POST',body:formData,}).then(res=>{
                var data=this.GetResponesData(res,key)
                if(data.code) resolve(data)
                else reject(data)
            })
        })
    }
    /**
        @param {string}         -filePath:文件路径
        @param {<string>}       -dir:需要存入的OSS路径(桶路径)
        @param {<string>}       -fileKye:接受的字段
        @return {Promise} 
    */
    UploadFileForUniapp(filePath,dir="",fileKye="file"){
        return new Promise((resolve,reject)=>{
            var key = this.GeneraterDefaultFileName(filePath,dir||this.OSS.bucketSrc)
            var {policy,signature} =this.GetSignatureWithPolicy()
            var {success_action_status,OSSAccessKeyId} =this.OSS
            var params={key,policy,signature,success_action_status,OSSAccessKeyId}
            uni.uploadFile({
            	url:this.OSS.OssAddress,
            	filePath: filePath,
            	name:fileKye,
            	formData:params,
            	success:(res)=>{
					var data=this.GetResponesData(res,key)
					if(data.code) resolve(data)
					else reject(data)
            	},
            	fail: (err)=>{
					var res=this.GetResponesData(err)
					reject(res)
				},
            })
        })
    }
	
	GetResponesData(res,key){
		var params={code:null,data:null}
		var resultCode=res.statusCode||res.status
		if(resultCode==this.OSS.success_action_status){
			params.code=1
			if(res.data)params.data=res.data
			else params.data=`${this.OSS.OssAddress}${key}`
		}else {
			params.code=0
			params.data=res
		}
		return params
	}
	
}

export default AliyunOSSRirect


