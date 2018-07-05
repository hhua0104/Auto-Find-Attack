#-*- coding:utf-8 -*-
import requests
import re
import sys
reload(sys)
sys.setdefaultencoding('utf8')
import ssl
ssl._create_default_https_context = ssl._create_unverified_context
import datetime
import json
import time
import urllib3
urllib3.disable_warnings()
from dingtalkchatbot.chatbot import DingtalkChatbot
# WebHook地址https://oapi.dingtalk.com/robot/send?access_token=dd9484b5e26ca3ccee2268a1379eee0178c751da4b463cece90bd79e83ef9dae
webhook = 'https://oapi.dingtalk.com/robot/send?access_token=dd9484b5e26ca3ccee2268a1379eee0178c751da4b463cece90bd79e83ef9dae'
# 初始化机器人小丁
xiaoding = DingtalkChatbot(webhook)
# Markdown消息@所有人
xiaoding.send_markdown(title='氧气文字', text='#### 广州天气\n'
                           '> 9度，西北风1级，空气良89，相对温度73%\n\n'
                           '> ![美景](http://www.sinaimg.cn/dy/slidenews/5_img/2013_28/453_28488_469248.jpg)\n'
                           '> ###### 10点20分发布 [天气](http://www.thinkpage.cn/) \n',
                           is_at_all=True)


def print_attack(runtime):
    url='https://172.16.1.245/api/v1/log?risk_level=high&action=allow&action=deny&offset=0&count=20'
    headers = {
               'Cookie': 'csrftoken=fH82jLN3NCd4LGRdG840vge7gEJZfyIQdyXvDuFUnnpACjrjYZ0N3ysTMwU0ZZCz; sessionid=mme8dlg2n00bt0dlwrkwf48hu53dxbjl',
               }
    req=requests.get(url,headers=headers,verify=False)
    data=json.loads(req.text)
    items= data["data"]["items"]
    province=items[0]["province"]
    temp_d = datetime.datetime.fromtimestamp(items[0]["timestamp"])
    now_time = temp_d.strftime("%Y-%m-%d %H:%M:%S")
    compare_time=items[0]["timestamp"]
    if int(compare_time)>int(runtime):
        dest_ip=items[0]["dest_ip"]
        host=items[0]["host"]
        src_ip=items[0]["src_ip"]
        reason=items[0]["reason"]
        print '发现攻击'
        message='时间：'+now_time+' 攻击源 '+src_ip+'（'+province+'） 被攻击系统：'+dest_ip+'（'+host+'）攻击方式：'+reason
        # Text消息@所有人
        xiaoding.send_text(msg=message, is_at_all=False)
        print message
        runtime=int(compare_time)
    return runtime
    #dest_ip
    #Host
    #timestamp
    #host
    #print items
    #print now_time
    #print data
    #print req.text

run_time=int(time.time())
i=1
while True:
    #print '第'+str(i)+'次：'+str(datetime.datetime.now())
    print '. ',
    i=i+1
    run_time=print_attack(run_time)
    time.sleep(10)

