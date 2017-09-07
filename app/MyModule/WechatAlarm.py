# -*- coding:utf-8 -*-
# Created on 07/27/2016
# By Peter Chen
# coding=utf-8

import json
import requests
import time
from ..models import TokenRecord
from .. import db, logger
import datetime
from .GetConfig import get_config


class WechatAlarm:
    def __init__(self):
        variable = {}
        tmp = get_config('wechat')

        variable['corpid'] = tmp['corpid']
        variable['corpsecret'] = tmp['corpsecret']
        self.expire_time = int(tmp['expire_time'])  # seconds
        self.get_token_url = 'https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=%s&corpsecret=%s'
        self.send_sms_url = 'https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=%s'
        self.headers = {'Content-Type': 'application/json', "encoding": "utf-8"}

        if_token = TokenRecord.query.filter_by(unique_id=variable['corpid']).first()

        if if_token:
            if (datetime.datetime.now() - if_token.create_time).seconds < (int(if_token.expire) - self.expire_time):
                self.access_token = if_token.token
            else:
                db.session.delete(if_token)
                self.access_token = self.get_token(variable)
        else:
            self.access_token = self.get_token(variable)

    def get_token(self, variable):
        r = requests.get(self.get_token_url % (variable['corpid'], variable['corpsecret']))
        js = r.json()
        print('Accessing %s ' % r.url)
        if js.get('errcode') == 0:
            print('Get access token %s successful' % js)
            access_token = js.get('access_token')
            expires_in = js.get('expires_in')
            token_record = TokenRecord(unique_id=variable['corpid'], token=access_token, expire=expires_in,
                                       create_time=time.localtime())
            db.session.add(token_record)
            db.session.commit()
            return access_token
        else:
            print('Get access token fail')
            return False

    def init_text(self, content):
        content = content
        print(content)
        send_content = {
            "touser": "@all",
            "toparty": "",
            "totag": "",
            "msgtype": "text",
            "agentid": "2",
            "text": {
                "content": content
            },
            "safe": "0"
        }

        return send_content

    def news_msg(self, **kwargs):
        title = kwargs.get('title')
        description = kwargs.get('description')
        web_url = kwargs.get('web_url')
        picurl = kwargs.get('picurl')
        send_content = {
            "touser": "@all",
            "toparty": "",
            "totag": "",
            "msgtype": "news",
            "agentid": "2",
            "news": {
                "articles": [
                    {
                        "title": title,
                        "description": description,
                        "url": web_url,
                        "picurl": picurl
                    }
                ]
            },
            "safe": "0"
        }

        return send_content

    def sendMsg(self, send_content):
        r = requests.post(self.send_sms_url % self.access_token,
                          data=json.dumps(send_content, ensure_ascii=False).encode('utf-8'), headers=self.headers)
        result = r.json()
        logger.debug(result)


