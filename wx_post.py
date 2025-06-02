from flask import Flask, request, jsonify, Blueprint
import requests
import time
import json

baoming_routes = Blueprint('报名', __name__)

# 从环境变量获取配置
APP_TOKEN = "AT_c9Lsghei4ICP7RwYQJrywzQT4tHupcVh"
WXPUSHER_URL = 'https://wxpusher.zjiecode.com/api/send/message'
UIDS = ['UID_sJAm6S1nIYepTCv3GHs0QN05YAHM']
UIDS = ['UID_sJAm6S1nIYepTCv3GHs0QN05YAHM', 'UID_C6sy8APLO6jtxoAdrcYllKBBHL9P', 'UID_h3pvFrqrG62Jk7PueoDllHADnClN', 'UID_dHm5br3JXmGYnbG9tjbBfPbOe6XZ']


def append_liuyan_json(dic, file_path="log.json"):
    data = json.load(open("log.json", "r", encoding="utf-8"))
    data.append(dic)
    json.dump(data, open("log.json", "w", encoding="utf-8"), indent=2, ensure_ascii=False)

def 课程卖出_通知管理员(课程,用户名,手机号,kw={}):
    timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    dic = {
        "购买课程": 课程,
        "购买用户": 用户名,
        "手机号": 手机号,
        "购买时间": timenow,
    }
    dic.update(kw)
    full_content = '\n'.join(f"{key}: {value}" for key, value in dic.items())
    append_liuyan_json(dic)

    response = requests.post(
        WXPUSHER_URL,
        json={
            'appToken': APP_TOKEN,
            'content': full_content,
            'contentType': 1,
            'uids': UIDS
        },
        timeout=5
    )
    wx_data = response.json()
    if wx_data.get('code') == 1000:
        return True
    return False


@baoming_routes.route('/submit_wx', methods=['POST'])
def handle_submit():
    data = request.get_json()
    content_type = data.get('type')  # phone1/phone2/message/signup
    content_data = data.get('data', {})

    # 验证提交类型
    if not content_type:
        return jsonify(success=False, error='无效的提交类型'), 400

    # 验证内容是否为空
    if not content_data:
        return jsonify(success=False, error='提交数据不能为空'), 400

    content_data["提交时间"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    append_liuyan_json(content_data)
    # 生成换行分隔的消息内容
    full_content = '\n'.join(f"{key}: {value}" for key, value in content_data.items())

    # 发送到 WxPusher
    try:
        response = requests.post(
            WXPUSHER_URL,
            json={
                'appToken': APP_TOKEN,
                'content': full_content,
                'contentType': 1,
                'uids': UIDS
            },
            timeout=5
        )
        response.raise_for_status()
        wx_data = response.json()

        if wx_data.get('code') == 1000:
            return jsonify(success=True)
        return jsonify(success=False, error=wx_data.get('msg')), 500

    except requests.exceptions.RequestException:
        return jsonify(success=False, error='网络连接失败'), 500
    except Exception:
        return jsonify(success=False, error='服务器处理失败'), 500
