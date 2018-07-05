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
# 测试用机器人
webhook = 'https://oapi.dingtalk.com/robot/send?access_token=dd9484b5e26ca3ccee2268a1379eee0178c751da4b463cece90bd79e83ef9dae'
# 检测分析组-雷池机器人
#webhook='https://oapi.dingtalk.com/robot/send?access_token=31945948c14e8f1dba6b9dcec0edac32b84d65791508fba3aa53139b9053e65e'
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
                elif all_data_tmp[j]["reason"].find(all_data[j1]["reason"]) == -1 and all_data[j1]["reason"].find(
                        all_data_tmp[j]["reason"]) == -1:
                    all_data[j1]["reason"] = all_data[j1]["reason"] +'、'+ all_data_tmp[j]["reason"]
                    all_data_tmp[j]["reason"] = all_data[j1]["reason"]
                break
            elif j == len(all_data_tmp) - 1:
                all_data.append(all_data_tmp[j])
        if len(all_data) == 0:
            all_data.append(all_data_tmp[j])
    return all_data_tmp

def print_attack(runtime,url,headers):
    req=requests.get(url,headers=headers,verify=False)
    data=json.loads(req.text)
    i=0
    items= data["data"]["items"]
    #print items
    compare_time=items[i]["timestamp"]
    all_data_tmp=[]

    while int(compare_time)>int(runtime):
        #print i
        #province=items[i]["province"]
        urlpath=items[i]["urlpath"]
        if urlpath.find('/%3Cdiv%20class=%22pagenav%22%3E%0A%09%3Cform%20name=%22fsmformvalue%22%20action=%22?%22%20')!=-1:
            i = i + 1
            compare_time = items[i]["timestamp"]
            continue
        dest_ip = items[i]["dest_ip"]
        host = items[i]["host"]
        src_ip = items[i]["src_ip"]
        #是否是内部ip
        isprivate_ip=0
        for ip1 in range(16,32):
            #print ip1
            if str(src_ip).find('172.'+str(ip1))!=-1:
                isprivate_ip = 1
                break
        if isprivate_ip==1:
            i = i + 1
            compare_time = items[i]["timestamp"]
            continue
        reason = items[i]["reason"]
        dest_port=items[i]["dest_port"]
        reason=reason[reason.find(' '):reason.find(' 攻击')].replace(' ','')
        #print reason
        temp_d = datetime.datetime.fromtimestamp(items[i]["timestamp"])
        now_time = temp_d.strftime("%Y-%m-%d %H:%M:%S")
        #print '发现攻击'
        message = ' 攻击源 ' + src_ip + '（' + get_address(src_ip) + '） 被攻击系统：' + dest_ip + '（' + host + '）'
        excel1=' ' + src_ip + ' ' + get_address(src_ip)
        excel2=' ' + dest_ip + ' '+str(dest_port)+' ' + host

        #首先将信息写入临时数组中，然后将临时数组与永久数组对比，如果没有就加入，如有就更新数量
        for j in range(0,len(all_data_tmp)):
            tmp=message
            if str(all_data_tmp[j]["data"]).find(tmp)!=-1:
                all_data_tmp[j]["num"]=all_data_tmp[j]["num"]+1
                if all_data_tmp[j]["reason"].find(reason)==-1:
                    all_data_tmp[j]["reason"] = all_data_tmp[j]["reason"] +'、'+ reason
                break
            elif j==len(all_data_tmp)-1:
                all_data_tmp.append({'time':now_time,'data': message, 'num': 1, 'reason': reason,'excel1':excel1,'excel2':excel2})
        if len(all_data_tmp)==0:
            all_data_tmp.append({'time':now_time,'data': message, 'num': 1, 'reason': reason,'excel1':excel1,'excel2':excel2})

        i=i+1
        if i>=len(items):
            break
        compare_time = items[i]["timestamp"]

    all_data_tmp=compare_data(all_data_tmp)

    for j in range(0,len(all_data_tmp))[::-1]:
        #print '发现攻击'
        #print '.'
        message1= '时间：' +all_data_tmp[j]["time"]+all_data_tmp[j]["data"]+' 攻击方式：' +all_data_tmp[j]["reason"]+' 攻击次数：' +str(all_data_tmp[j]["num"])+' 发现系统：雷池'
        #日期	时间	攻击源IP	攻击源城市	攻击次数	目的IP	目的端口	目的系统名称	攻击手法	发现设备
        message2= all_data_tmp[j]["time"]+' '+str(all_data_tmp[j]["excel1"])+' '+str(all_data_tmp[j]["num"])+' '+str(all_data_tmp[j]["excel2"]) +' '+all_data_tmp[j]["reason"]+' 雷池'

        #message2是导出报表格式，请把message1禁用
        time_excel=datetime.datetime.strptime(all_data_tmp[j]["time"], "%Y-%m-%d %H:%M:%S")
        time_excel2=str(time_excel.month)+'.'+str(time_excel.day)+' '+str(time_excel.hour)+':'+str(time_excel.minute)
        #print str(message2).replace(all_data_tmp[j]["time"],time_excel2)
        with open('safeline.txt', 'a+') as f:
            f.write(str(message2).replace(all_data_tmp[j]["time"],time_excel2)+'\n')
        #message1是普通播报
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

run_time1 = datetime.datetime.strptime("2018-07-05 20:00:00", "%Y-%m-%d %H:%M:%S")
run_time2 = time.mktime(run_time1.timetuple())
run_time=int(run_time2)
pagesize=500
#run_time=int(time.time())
i=1
temp_d1 = datetime.datetime.fromtimestamp(run_time)
with open('safeline.txt', 'a+') as f:
    f.write('本次发现攻击开始时间：'+temp_d1.strftime("%Y-%m-%d %H:%M:%S")+'\n')
while True:
    #print '第'+str(i)+'次：'+str(datetime.datetime.now())
    i=i+1

    headers = {
               'Cookie': 'csrftoken=gTPngeSoFTRg8cLpx1I9JxKdf9ibGcBAPZ4E8yPZCW1eXqAJWCIYKJRJ7DlXVUaM; sessionid=surfze305whe8xmcea0090owyksdn1aw',
               }

    try:
        url = 'https://172.16.1.245/api/v1/log?risk_level=high&action=allow&action=deny&count='+str(pagesize)+'&offset=0'
        # print url
        run_time = print_attack(run_time, url,headers)
        print '. ',
        # run_time=int(time.time())
        time.sleep(30)
    except e:
        print e.message

