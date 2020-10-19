from alipay_dc_client import AlipayDcClient

APP_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKC0qVPjT4PjTqL609kDKZPQHvn80T9hvyUI3DwcnMJX/93Q/T0NvKSUBH/4HW2dCFjfms9fGFUArDHWz1SePNWJLT2HfnZ7U0B4wNnmg7cX11KMKrY6KbgIGVJgN5UTwIDAQABAoIBAQCxIvQX/fxewB9VDKWoSW99NtP/zhZBClTCia+/7TXw0XaVzNwhH65BMyJtkE6Hw28C4KMCRNQZVlHuBzkEu2TPNnvzZX34JQPM6tcdd/NAGUzpbjOcJOthXvy7j1PuB0Gy/KxSyYskEa6AFA6bf26oQzaKvo2C5DKwGkJjWmazO1ntil74nd/zGSTtabGbh2rBpqktMMwtRxhPHu3qVxm/pmq4u5mrYXYvOEGEaYtGIyA102PmcBdZU76qTiF/47STMLoIfKZBsQtZbtXBh7/FlZLYhvfJ8fHK44uCU4+4/RCApNAGtJ2HAKiPxgTQPVr/WICS34LQDW+V+TbfsxnhAoGBAORVkIwyaFbdDOAiA9zXwIdpr+uxkwfF+456DGg84+2+GaGZEx0No9IOs3McGQFo8MNwGUMSsNaCZov9SAWwYrQ5fj1Jf4oEV74eHUas+2asBteH3fDAzT0ZodrfxT7S3erej7ZrLYj1Go+p0y3LvFd9EiiTLUIShSLB8vYk6eHJAoGBAMoGFbsDoaRADZZuFbxcG38S7dKVf6bwe+D3Rx/QEpQzAdJasCyT977G2B68gT46dpORpoqoIWv/ZMj0TktxfAsFUsJRTbFqxKYZzpWi10xE2G8uD+1vdlIY2tQ0VI2SLlXRZ8FlpSTjckl4DDMCmQNNvYOnM5xioKwaK3tWYlFXAoGAAnIgMEBB+dw4TRZQMEdnWov5RG8MgiLOxQHtrBgq4NsObzqyh7cjsBZUOcFtSySSn6VNv/gtSL7w1kMKSHVROVj8Ty/AW/wb7H9qFN25e6oQELL136RRDnx9zVhkRn3/vopPw8Z2IGdvt2Y8SttJ0y4VybV54KFOJ8coERboInECgYEAj5vRuLY1ImgyAHxS0Sn8ldFj461IJ+iNdvbwxUmI23aC1gCHebjZhPEe0oKXsR+oCPChnbE0yOusvjkEqxaJ4d+v29glzXejQJvZwX8XYu0Rmb75rYPtbSCj9fMZI+YFMBYClnTl9xoDtPw0V9KB6NpLXJnv0zw9EPotbKiUjVMCgYA2cISXs2ZSxiF+DCSUb7oi8jgZX8pKx2ZNIgdqiGZ7GklmgEutXzkTsBiqCSayTG5yRrY6ECDFZ0GShHBhAtPclKFU6/tO+lE8eiwvnOPAZlJ4CwyAUHQcw03FT9LxLQEw9aSD4jVx611J4Jgj+1b3jncCs5PtOgoV65X+sonRVg==\n-----END RSA PRIVATE KEY-----"
APP_PUBLIC_KEY_CERT_STRING = """-----BEGIN CERTIFICATE-----
MIIEuzCCA6OgAwIBAgIQICAQBGh1+HHaaPpibBR47jANBgkqhkiG9w0BAQsFADCBgjELMAkGA1UE
BhMCQ04lzr6re16NvmkGd/t1JAUiYAhJz0px2X4ywO
aKuOWBx8+Eaf+WPfj/oR4rvK9sDih6zmT3j/6pFKLSpCFslX1p3d2nLZJBgnZ288pv0S6OlKeBO7
khqJ3utXeBhma/V75/HxUODpjBhFMSHOuafFxi4oLU/+PvTsPgg6ficC7I9hFIHL9wtbLddGMqKr
ywI+q0M9gCCBXfy5L7FhCTTD
-----END CERTIFICATE-----"""
ALIPAY_PUBLIC_KEY_CERT_STRING = """-----BEGIN CERTIFICATE-----
MIIDuzCCAqOgAwIBAgIQICAJJ01Wz1d0J5K9O3zYozANBgkqhkiG9w0BAQsFADCBgjELMAkGA1UE
BhMCQ04xFjAUBgNVBAoMDUFudCBGaW5hbmNpYWwxIDAeBgNVBAsMF0NlcnRpZmljYXRpb24gQXV0
aG9yaXR5MTkwkQIDAQABoxIwEDAOBgNVHQ8BAf8EBAMCA/gw
DQYJKoZIhvcNAQELBQADggEBmRZckeffOaUMLTMz1mU2VYtMmxT8r
F/6S2c3xCysQ/vaDT0Q+2I1gB5G4N536yPWFj7dSIZ5EXcH7Nevmdp8O1edUm1c=
-----END CERTIFICATE-----"""
ALIPAY_ROOT_CERT_STRING = """-----BEGIN CERTIFICATE-----
MIIBszCCAVegAwIBAgIIaeL+wBcKxnswDAYIKoEcz1UBg3UFADAuMQswCQYDVQQG
EwJDTjEOMAwGA1UECgwFTlJDQUMxDzANBgNVBAMMBlJPT1RDQTAeFw0xMjA3MTQw
MzExNTlaFw00MjA3MDcwMzExNTlaMC4xCzAJBgNVBAYTAkNOMQ4wDAYDVQQKDAVO
UkNBQzEPMA0GA1UEADSAAwRQIgG1bSLeOXp3oB8H7b
53W+CKOPl2PknmWEq/lMhtn25HkCIQDaHDgWxWFtnCrBjH16/W3Ezn7/U/Vjo5xI
pDoiVhsLwg==
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIF0zCCA7ugAwIBAgIIH8+hjWpIDREwDQYJKoZIhvcNAQELBQAwejELMAkGA1UE
BhMCQ04xFjAUBgNVBAoMDUFudCBGaW5hbmNpYWwxIDAeBgNVBAsMF0NlcnRpZmlj
YXRpb24gQXV0aG9ya2Ei9WfUyxFjVO1LVh0Bp
dRBeWLMkdudx0tl3+21t1apnReFNQ5nfX29xeSxIhesaMHDZFViO/DXDNW2BcTs6
vSWKyJ4YIIIzStumD8K1xMsoaZBMDxg4itjWFaKRgNuPiIn4kjDY3kC66Sl/6yTl
YUz8AybbEsICZ5Y
jXayv+NLbidOSzk4vl5QwngO/JYFMkoc6i9LNwEaEtR9PhnrdubxmrtM+RjfBm02
77q3dSWFESFQ4QxYWew4pHE0DpWbWy/iMIKQ6UZ5RLvB8GEcgt8ON7BBJeMc+Dyi
kT9qhqn+lw==
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIICiDCCAgygAwIBAgIIQX76UsB/30owDAYIKoZIzj0EAwMFADB6MQswCQYDVQQG
EwJDTjEWMBQGA1UECgwNQW50ILp6sg
wHfPiOr9gxreb+e6Oidwd2LDnC4OUqCWiF8CMAzwKs4SnDJYcMLf2vpkbuVE4dTH
Rglz+HGcTLWsFs4KxLsq7MuU+vJTBUeDJeDjdA==
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIDxTCCAq2gAwIBAgIUEMdk6dVgOEIS2cCP0Q43P90Ps5YwDQYJKoZIhvcNAQEF
BQAwajELMAkGA1UEBhMCQ04xEzARBgNVBAoMCmlUcnVzQ2hpbmExHDAaBgNVBAsM
E0NoaW5hIFRydXN0IE5ldHdvcmsxKDAmBgNVBAMMH2lUcnVzQ2hpbmEgQ2xhc3Mg
MiBSb290IENBIC0gRzMwHhcNMTeyI9LdxIVa1RjVX8pYOj8JFwtn
DJN3ftSFvNMYwRuILKuqUYSHc2GPYiHVflDh5nDymCMOQFcFG3WsEuB+EYQPFgIU
1DHmdZcz7Llx8UOZXX2JupWCYzK1XhJb+r4hK5ncf/w8qGtYlmyJpxk3hr1TfUJX
Yf4Zr0fJsGuv
-----END CERTIFICATE-----"""
ALIPAY_APP_ID = "APPID"
client = AlipayDcClient(
    appid=ALIPAY_APP_ID,
    app_notify_url="",
    app_private_key_string=APP_PRIVATE_KEY,
    app_public_key_cert_string=APP_PUBLIC_KEY_CERT_STRING,
    alipay_public_key_cert_string=ALIPAY_PUBLIC_KEY_CERT_STRING,
    alipay_root_cert_string=ALIPAY_ROOT_CERT_STRING,
    debug=True
)


def transfer():
    out_biz_no = ""
    payee_type = "ALIPAY_LOGONID"
    payee_account = ""
    amount = "0.12"
    remark = "test0.12"
    r = client.api("alipay.fund.trans.toaccount.transfer",
                   biz_content={
                       "out_biz_no": out_biz_no,
                       "payee_type": payee_type,
                       "payee_account": payee_account,
                       "amount": amount,
                       "remark": remark,
                   })
    print(r)


def oauth():
    r = client.api("alipay.system.oauth.token",
                   grant_type="authorization_code",
                   code="123")
    print(r)