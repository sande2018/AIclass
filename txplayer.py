#!/usr/bin/python
#coding=utf-8

import jwt
import time
from datetime import datetime
import hashlib
import datetime
from AES import encrypt,decrypt 

def 获取过期时间戳(hours=10):
    now = datetime.datetime.now()
    future_time = now + datetime.timedelta(hours)
    future_timestamp = future_time.timestamp()
    return int(future_timestamp)


def md5_encrypt(文件名,到期时间):
    m = f"cdn.gzturing.com|{文件名}|2025|{到期时间}"
    return hashlib.md5(m.encode()).hexdigest()


def get_tx_url(uu):
    file_name = uu.split('||')[0]
    timestamp = 获取过期时间戳(10)
    m = md5_encrypt(file_name,timestamp)
    if "http" not in uu:
        
        return f"https://cdn.gzturing.com:8624/embed?name={encrypt(file_name)}&m={m}&timestamp={timestamp}"
        
    # return file_name

    return "https://1500036001.vod-qcloud.com/6cd10492vodcq1500036001/c783c70e1397757907190259431/f0.mp4"
    
    domain,FileId = uu.split('||')
    当前时间 = int(datetime.now().timestamp()) #int(time.time())
    AppId = 1335108353 #用户 appid
    FileId = f'{FileId}' #目标 FileId
    AudioVideoType = "RawAdaptive" #播放的音视频类型
    RawAdaptiveDefinition = 20 #允许输出的未加密的自适应码流模板 ID
    # ImageSpriteDefinition = 10 #做进度条预览的雪碧图模板 ID
    CurrentTime = 当前时间
    PsignExpire = 当前时间+36000 #可任意设置过期时间
    UrlTimeExpire = "" #可任意设置过期时间
    PlayKey = "W6gH7RpblVKtmTXSBRnJ"

    Original = {
      "appId": AppId,
      "fileId": FileId,
      "currentTimeStamp": CurrentTime,
      "contentInfo": {
        "audioVideoType": "Original",
        "imageSpriteDefinition": 10
      },
      "expireTimeStamp": PsignExpire,
      "urlAccessInfo": {
        "domain": domain,
        "scheme": "HTTPS",
        "exper": 30,#试看30秒
        "rlimit": 1,#限制IP数量
        "ghostWatermarkInfo": "朱永彬",
      }
    }

    Signature = jwt.encode(Original, PlayKey, algorithm='HS256')
    # print("Original: ", Original)
    # print("Signature: ", Signature)
    return f'https://{domain}/vod-player/{domain.split(".")[0]}/{FileId}/vod/vod-player-v4.html?autoplay=false&width=1920&height=1080&psign={Signature}&lang=zh-CN'

if __name__ == '__main__':
    print(get_tx_url('1335108353.vod-qcloud.com||1397757906773610524'))