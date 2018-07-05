#-*- coding:utf-8 -*-
import requests
import re
import sys
import Image as img
import Image, ImageDraw, ImageFont, ImageFilter
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

all_data=[]
def get_address(ip):
    con1 = requests.get("http://ip.ws.126.net/ipquery?ip=%s" % ip)
    #print con1.content
    #print '111'
    #print chardet.detect(con1.content)
    return re.findall('lo="(.*?)",',con1.content)[0].decode( "GB2312")

def compare_data(all_data_tmp):
    # 将临时数组与永久数组对比，如果没有就加入，如有就更新数量
    for j in range(0, len(all_data_tmp)):
        for j1 in range(0, len(all_data)):
            if str(all_data_tmp[j]["data"]).find(str(all_data[j1]["data"])) != -1:
                all_data_tmp[j]["num"] = all_data_tmp[j]["num"] + all_data[j1]["num"]
                all_data[j1]["num"] = all_data_tmp[j]["num"]
                if all_data_tmp[j]["reason"].find(all_data[j1]["reason"]) == -1 and all_data[j1]["reason"].find(
                        all_data_tmp[j]["reason"]) != -1:
                    all_data_tmp[j]["reason"] = all_data[j1]["reason"]
                elif all_data_tmp[j]["reason"].find(all_data[j1]["reason"]) != -1 and all_data[j1]["reason"].find(
                        all_data_tmp[j]["reason"]) == -1:
                    all_data[j1]["reason"] = all_data_tmp[j]["reason"]
                else:
                    all_data[j1]["reason"] = all_data[j1]["reason"] + all_data_tmp[j]["reason"]
                    all_data_tmp[j]["reason"] = all_data[j1]["reason"]
                break
            elif j == len(all_data_tmp) - 1:
                all_data.append(all_data_tmp[j])
        if len(all_data) == 0:
            all_data.append(all_data_tmp[j])
    return all_data_tmp

def print_attack(runtime):
    url='https://172.16.1.245/api/v1/log?risk_level=high&action=allow&action=deny&offset=0&count=100'
    headers = {
               'Cookie': 'csrftoken=fH82jLN3NCd4LGRdG840vge7gEJZfyIQdyXvDuFUnnpACjrjYZ0N3ysTMwU0ZZCz; sessionid=mme8dlg2n00bt0dlwrkwf48hu53dxbjl',
               }
    req=requests.get(url,headers=headers,verify=False)
    data=json.loads(req.text)
    i=0
    items= data["data"]["items"]
    compare_time=items[i]["timestamp"]
    all_data_tmp=[]

    while int(compare_time)>int(runtime):
        #province=items[i]["province"]
        urlpath=items[i]["urlpath"]
        if urlpath.find('/%3Cdiv%20class=%22pagenav%22%3E%0A%09%3Cform%20name=%22fsmformvalue%22%20action=%22?%22%20')!=-1:
            i = i + 1
            compare_time = items[i]["timestamp"]
            continue
        dest_ip = items[i]["dest_ip"]
        host = items[i]["host"]
        src_ip = items[i]["src_ip"]
        reason = items[i]["reason"]
        temp_d = datetime.datetime.fromtimestamp(items[i]["timestamp"])
        now_time = temp_d.strftime("%Y-%m-%d %H:%M:%S")
        #print '发现攻击'
        message = ' 攻击源 ' + src_ip + '（' + get_address(src_ip) + '） 被攻击系统：' + dest_ip + '（' + host + '）'

        #首先将信息写入临时数组中，然后将临时数组与永久数组对比，如果没有就加入，如有就更新数量
        for j in range(0,len(all_data_tmp)):
            tmp=message
            if str(all_data_tmp[j]["data"]).find(tmp)!=-1:
                all_data_tmp[j]["num"]=all_data_tmp[j]["num"]+1
                if all_data_tmp[j]["reason"].find(reason)==-1:
                    all_data_tmp[j]["reason"] = all_data_tmp[j]["reason"] + reason
                break
            elif j==len(all_data_tmp)-1:
                all_data_tmp.append({'time':now_time,'data': message, 'num': 1, 'reason': reason, 'urlpath': host+urlpath})
        if len(all_data_tmp)==0:
            all_data_tmp.append({'time':now_time,'data': message, 'num': 1, 'reason': reason, 'urlpath': host+urlpath})

        i=i+1
        if i>=100:
            break
        compare_time = items[i]["timestamp"]

    all_data_tmp=compare_data(all_data_tmp)

    for j in range(0,len(all_data_tmp)):
        print '发现攻击'
        message1= '时间：' +all_data_tmp[j]["time"]+all_data_tmp[j]["data"]+' 攻击方式：' +all_data_tmp[j]["reason"]+' 攻击次数：' +str(all_data_tmp[j]["num"])+str(all_data_tmp[j]["urlpath"])
        print message1
        #xiaoding.send_text(msg=message1, is_at_all=False)
    runtime = int(items[0]["timestamp"])
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
    i=i+1
    run_time =print_attack(run_time)
    print '. ',
    #run_time=int(time.time())
    time.sleep(30)

