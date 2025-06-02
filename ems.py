from flask import Flask, request, jsonify,Blueprint
import json
import requests
import time
import hmac
import hashlib
import base64
import urllib.parse
import wx_post
import re

ems_bp = Blueprint('ems', __name__)


# 阿里云短信 API 配置
ACCESS_KEY_ID = "LTAI5tHkx6AiF6mqvaSYac31"
ACCESS_KEY_SECRET = "OzIhPbahlMm2SJ7zNdhdGT3npFw1Fr"
SIGN_NAME = "广州图灵"
TEMPLATE_CODE = "SMS_481065054"
SMS_URL = "https://dysmsapi.aliyuncs.com"

def sign_parameters(params, access_key_secret):
    """ 生成阿里云 API 请求签名 """
    sorted_params = sorted(params.items())
    query_string = "&".join("{}={}".format(urllib.parse.quote(k, safe=''), urllib.parse.quote(v, safe='')) for k, v in sorted_params)
    string_to_sign = "GET&%2F&" + urllib.parse.quote(query_string, safe='')

    h = hmac.new((access_key_secret + "&").encode(), string_to_sign.encode(), hashlib.sha1)
    signature = base64.b64encode(h.digest()).decode()
    return signature

def send_sms(phone_number, name, course_name,kw={}):
    wx_post.课程卖出_通知管理员(course_name,name,phone_number,kw)
    
    course_name = re.findall(r"[\w\u4e00-\u9fa5]+",course_name)[-1]
    # return ""
    """ 发送短信 """
    params = {
        "PhoneNumbers": str(phone_number),
        "SignName": SIGN_NAME,
        "TemplateCode": TEMPLATE_CODE,
        "TemplateParam": json.dumps({"name": str(name).rstrip("1234567890"), "course_name": str(course_name)}),
        "Action": "SendSms",
        "Version": "2017-05-25",
        "AccessKeyId": ACCESS_KEY_ID,
        "Timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "Format": "JSON",
        "SignatureMethod": "HMAC-SHA1",
        "SignatureVersion": "1.0",
        "SignatureNonce": str(int(time.time() * 1000))
    }

    # 生成签名
    params["Signature"] = sign_parameters(params, ACCESS_KEY_SECRET)

    # 发送请求
    response = requests.get(SMS_URL, params=params)
    return response.json()

@ems_bp.route('/send_sms', methods=['POST'])
def send_sms_api():
    return ""
    """ 处理短信发送请求 """
    data = request.json
    phone_number = data.get("phone_number")
    name = data.get("name")
    course_name = data.get("course_name")

    if not phone_number or not name or not course_name:
        return jsonify({"error": "缺少必要参数"}), 400

    result = send_sms(phone_number, name, course_name)
    return jsonify(result)


if __name__ == '__main__':

    print(send_sms(15521397691, "猪猪侠", "人工智能训练师-数据智能应用"))