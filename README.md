## 支付宝接口加签-公钥证书方式非官方sdk

>> 吐槽：官方 python sdk 太臃肿了，而且不支持公钥证书签名。

### 注意：生成 csr 文件，选择 PKCS1 格式（默认选择的是PKCS8），才能适用 python

使用普通公钥方式加签支付宝接口，不能使用支付宝资金出口类接口。

为了避免日后切换的麻烦，推荐使用支付宝**公钥证书**方式加签所有接口，可以同时支持支付宝资金出口类接口。

## 支付宝接口官方文档

api 文档地址：

https://opendocs.alipay.com/apis 

自行实现加签：

https://opendocs.alipay.com/open/291/106118

公钥证书配置：

https://opendocs.alipay.com/open/291/105971

### 注意：生成 csr 文件，选择 PKCS1 格式（默认选择的是PKCS8），才能适用 python

## 功能

- 本客户端只提对接口请求进行签名、对响应验证签名的功能，不集成具体接口。
- 支持且仅支持支付宝 API 以**公钥证书**方式加签。
- 具体请求接口，请参看支付宝官方文档 。
- 配置好**签名证书**加签方式，可以使用本客户端便捷访问支付宝所有接口。
- 支付宝 api 地址 https://opendocs.alipay.com/apis

## 安装

安装时会同时安装以下两个库：

    pycryptodome
    pyOpenSSL

## 示例
    # 初始化客户端
    client = AlipayDcClient(
        # appid
        appid=ALIPAY_APP_ID,
        # 异步回调地址，什么时候能用到，参看支付宝官方文档
        app_notify_url="https://your_notify_url.com/notify_path",
        # APP 私钥 字符串
        app_private_key_string=APP_PRIVATE_KEY,
        # APP 公钥证书 字符串
        app_public_key_cert_string=APP_PUBLIC_KEY_CERT_STRING,
        # 支付宝 公钥证书 字符串
        alipay_public_key_cert_string=ALIPAY_PUBLIC_KEY_CERT_STRING,
        # 支付宝 根证书 字符串
        alipay_root_cert_string=ALIPAY_ROOT_CERT_STRING,
        # 调试日志
        debug=True
    )
    # 资金出口接口，示例
    # 其他接口同样，可以照葫芦画瓢
    # 文档地址 https://opendocs.alipay.com/apis/api_28/alipay.fund.trans.toaccount.transfer
    # 只需要将业务参数填入，client 会自动处理公共参数、和签名
    out_biz_no = ""
    payee_type = ""
    payee_account = ""
    amount = ""
    remark = ""
    r = client.api("alipay.fund.trans.toaccount.transfer",
                   biz_content={
                       "out_biz_no": out_biz_no,
                       "payee_type": payee_type,
                       "payee_account": payee_account,
                       "amount": amount,
                       "remark": remark,
                   })
    print(r)
    # {'code': '40004', 'msg': 'Business Failed', 'sub_code': 'INVALID_PARAMETER', 'sub_msg': '参数有误。out_biz_no:参数out_biz_no不能为空字符串'}
    ##############################
    # 换取授权访问令牌接口，示例
    # 其他接口同样，可以照葫芦画瓢
    # 文档地址 https://opendocs.alipay.com/apis/api_9/alipay.system.oauth.token
    # 注意该接口没有 biz_content 参数，无需填入
    # 只需要将业务参数填入，client 会自动处理公共参数、和签名
    r = client.api("alipay.system.oauth.token",
                   grant_type="authorization_code",
                   code="your code")
    print(r)
   