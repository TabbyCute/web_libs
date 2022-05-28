class LibEnvConfig {
    OSS={
        success_action_status:200,                                          //上传成功后的网络响应码
        OssAddress:`http://wh-fy.oss-cn-hangzhou.aliyuncs.com/`,   // OSS地址
        bucketSrc:"fy_talk_file/",                                             // 需要存入的oss路径
        AccessKeySecret:'ijVL6QvEbdIbAoe4xHBKma5wCeNNz9',               //
        OSSAccessKeyId:'LTAI5t7dF1GY84Xa6JW3wxUw',                     //
        timeout:87600,                                          //这个是上传文件时Policy的失效时间
        conditions:[["content-length-range",0,1024*3000]],       //规则          //生成policy如果没有可能报400
    }
}


export default LibEnvConfig