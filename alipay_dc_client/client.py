#!/usr/bin/env python
# coding: utf-8

import json
import logging
from datetime import datetime

import hashlib

import OpenSSL

from urllib.parse import quote_plus
from urllib.request import urlopen
from base64 import decodebytes, encodebytes

# 常见加密算法
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from alipay_dc_client.alipay_dc_client_exception import AliPayException, AliPayValidationError

SUPPORT_ALG_LIST = (
    b'rsaEncryption',
    b'md2WithRSAEncryption',
    b'md5WithRSAEncryption',
    b'sha1WithRSAEncryption',
    b'sha256WithRSAEncryption',
    b'sha384WithRSAEncryption',
    b'sha512WithRSAEncryption'
)


def get_app_cert_sn(cert_str):
    """
    获取证书 SN 算法
    """
    cert = _load_certificate(cert_str)
    return _get_cert_sn_from_certificate(cert)


def get_alipay_root_cert_sn(root_cert_string):
    """
    实际就是好几个证书，使用 _get_cert_sn_from_certificate(cert) 后，拼接的字符串
    :param root_cert_string:
    :return:
    """
    cert_str_list = [i for i in root_cert_string.split('\n\n') if i]
    certs = [_load_certificate(cert) for cert in cert_str_list]
    root_cert_sn_list = []
    for cert in certs:
        try:
            sign_alg = cert.get_signature_algorithm()
        except ValueError:
            continue
        if sign_alg in SUPPORT_ALG_LIST:
            cert_sn = _get_cert_sn_from_certificate(cert)
            root_cert_sn_list.append(cert_sn)
    return "_".join(root_cert_sn_list)


def _get_cert_sn_from_certificate(cert):
    cert_issuer = cert.get_issuer()
    name = f'CN={cert_issuer.CN},OU={cert_issuer.OU},O={cert_issuer.O},C={cert_issuer.C}'
    string = name + str(cert.get_serial_number())
    return hashlib.md5(string.encode()).hexdigest()


def _load_certificate(cert_str):
    """
    FILETYPE_PEM 加载证书
    :param cert_str: str的证书
    :return: 加载后的证书
    """
    return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_str)


def _sorted_data(data):
    for k, v in data.items():
        if isinstance(v, dict):
            # 将字典类型的数据dump出来
            data[k] = json.dumps(v, separators=(',', ':'))
    return sorted(data.items())


class AlipayDcClient:
    """
     数字证书 (digital certificate) 版本
     """

    def __init__(
            self,
            appid,
            app_notify_url,
            app_private_key_string,
            app_public_key_cert_string,
            alipay_public_key_cert_string,
            alipay_root_cert_string,
            debug=False
    ):
        """
        DCAlipay(
            appid='',
            app_notify_url='http://example.com',
            app_private_key_string='',
            app_public_key_cert_string='',
            alipay_public_key_cert_sring='',
            aplipay_root_cert_string='',
        )
        :param appid:
        :param app_notify_url:
        :param app_private_key_string:
        :param app_public_key_cert_string:
        :param alipay_public_key_cert_string:
        :param alipay_root_cert_string:
        :param debug:
        """
        # appid
        self._appid = str(appid)
        # 异步通知地址
        self._app_notify_url = app_notify_url
        # 仅支持 rsa2
        self._sign_type = "RSA2"
        # 支付宝根证书 sn
        self._alipay_root_cert_sn = get_alipay_root_cert_sn(alipay_root_cert_string)
        # app公钥证书sn
        self._app_cert_sn = get_app_cert_sn(app_public_key_cert_string)

        # 应用私钥
        self._app_private_key = RSA.importKey(app_private_key_string)
        # 支付宝公钥
        alipay_public_key_cert = _load_certificate(alipay_public_key_cert_string)
        alipay_public_key_string = OpenSSL.crypto.dump_publickey(
            OpenSSL.crypto.FILETYPE_PEM, alipay_public_key_cert.get_pubkey()
        ).decode("utf-8")
        self._alipay_public_key_string = alipay_public_key_string
        self._alipay_public_key = RSA.importKey(self._alipay_public_key_string)
        # debug log
        if debug:
            logging.basicConfig(level=logging.DEBUG)
        self._gateway = "https://openapi.alipay.com/gateway.do"

    def api(self, api_name, biz_content: dict = None, **kwargs):
        """
        通用接口，输入api名称，自动生成接口
        :param api_name: api名称例如：alipay.trade.order.settle
        :param biz_content: biz_content参数，没有就不用理他
        :param kwargs: 接口其他参数，不在biz_content里面的
        :return:
        """
        data = self._build_request_body(api_name,
                                        return_url=None,
                                        notify_url=None,
                                        biz_content=biz_content,
                                        **kwargs)
        logging.debug("请求参数=" + str(data))
        response_key = f"{api_name}_response".replace(".", "_")
        logging.debug("response_key=" + response_key)
        return self.verified_sync_response(data, response_key)

    @property
    def appid(self):
        return self._appid

    @property
    def sign_type(self):
        return self._sign_type

    @property
    def app_private_key(self):
        return self._app_private_key

    @property
    def alipay_public_key(self):
        return self._alipay_public_key

    def _sign(self, unsigned_string):
        # 计算签名
        key = self.app_private_key
        signer = PKCS1_v1_5.new(key)
        signature = signer.sign(SHA256.new(unsigned_string.encode()))
        # base64 编码，转换为unicode表示并移除回车
        sign = encodebytes(signature).decode().replace("\n", "")
        return sign

    def _build_request_body(self,
                            method: str,
                            return_url: str = None,
                            notify_url: str = None,
                            biz_content: dict = None,
                            **kwargs):
        data = {
            "app_id": self._appid,
            "method": method,
            "charset": "utf-8",
            "sign_type": self._sign_type,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "version": "1.0",
        }
        if biz_content is not None:
            data["biz_content"] = biz_content
        data.update(kwargs)

        if return_url is not None:
            data["return_url"] = return_url

        if method in (
                "alipay.trade.app.pay",
                "alipay.trade.wap.pay",
                "alipay.trade.page.pay",
                "alipay.trade.pay",
                "alipay.trade.precreate",
        ) and (notify_url or self._app_notify_url):
            data["notify_url"] = notify_url or self._app_notify_url
        data["app_cert_sn"] = self.app_cert_sn
        data["alipay_root_cert_sn"] = self.alipay_root_cert_sn
        return data

    def sign_data(self, data):
        data.pop("sign", None)
        ordered_items = _sorted_data(data)
        raw_string = "&".join("{}={}".format(k, v) for k, v in ordered_items)
        sign = self._sign(raw_string)
        unquoted_items = ordered_items + [('sign', sign)]
        signed_string = "&".join("{}={}".format(k, quote_plus(v)) for k, v in unquoted_items)
        return signed_string

    def _verify(self, raw_content, signature):
        """
        验证签名
        :param raw_content: 待签名的字符串
        :param signature: 待验证的签名
        :return:
        """
        key = self.alipay_public_key
        signer = PKCS1_v1_5.new(key)
        digest = SHA256.new()
        digest.update(raw_content.encode())
        return bool(signer.verify(digest, decodebytes(signature.encode())))

    def verify(self, data, signature):
        if "sign_type" in data:
            sign_type = data.pop("sign_type")
            if sign_type != self._sign_type:
                raise AliPayException(None, "Unknown sign type: {}".format(sign_type))
        # 排序后的字符串
        unsigned_items = _sorted_data(data)
        message = "&".join(u"{}={}".format(k, v) for k, v in unsigned_items)
        return self._verify(message, signature)

    def verified_sync_response(self, data, response_type):
        url = self._gateway + "?" + self.sign_data(data)
        logging.debug("请求地址=" + url)
        raw_string = urlopen(url).read().decode()
        logging.debug("支付宝返回数据=" + raw_string)
        return self._verify_alipay_response(raw_string, response_type)

    def _verify_alipay_response(self, raw_string, response_type):
        """
        return response if verification succeeded, raise exception if not

        As to issue #69, json.loads(raw_string)[response_type] should not be returned directly,
        use json.loads(plain_content) instead

        failed response is like this
        {
          "alipay_trade_query_response": {
            "sub_code": "isv.invalid-app-id",
            "code": "40002",
            "sub_msg": "无效的AppID参数",
            "msg": "Invalid Arguments"
          }
        }
        """
        response = json.loads(raw_string)
        # 返回内容中没有签名字段
        if "sign" not in response.keys():
            result = response[response_type]
            raise AliPayException(
                code=result.get("code", "0"),
                message=raw_string
            )

        sign = response["sign"]
        if response_type not in response.keys():
            # 有的时候返回的 key 是 error_response
            plain_content = self._get_signed_string(raw_string, "error_response")
        else:
            plain_content = self._get_signed_string(raw_string, response_type)
        logging.debug("待签名字符串为=" + plain_content)
        if not self._verify(plain_content, sign):
            raise AliPayValidationError
        return json.loads(plain_content)

    def _get_signed_string(self, raw_string: str, response_key):
        """
        https://docs.open.alipay.com/200/106120
        """
        # 括号匹配算法,碰到{则入栈，碰到}则出栈
        # 栈内为空，则匹配成功
        stack = []
        logging.debug(f"_get_signed_string-->response_key={response_key}")
        start_index = raw_string.find("{", raw_string.find(response_key))
        logging.debug(f"_get_signed_string-->start_index={start_index}")
        end_index = start_index
        for i, char in enumerate(raw_string[start_index:], start_index):
            logging.debug(f"_get_signed_string-->for={i}->{char}")
            if char == "{":
                stack.append("{")
            elif char == "}":
                stack.pop()
                if len(stack) == 0:
                    end_index = i + 1
                    break

        logging.debug(f"_get_signed_string-->end_index={end_index}")
        signed_str = raw_string[start_index:end_index]
        return signed_str

    @property
    def app_cert_sn(self):
        return getattr(self, "_app_cert_sn")

    @property
    def alipay_root_cert_sn(self):
        return getattr(self, "_alipay_root_cert_sn")
