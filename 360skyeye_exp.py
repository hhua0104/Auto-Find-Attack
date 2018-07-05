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
#webhook = 'https://oapi.dingtalk.com/robot/send?access_token=dd9484b5e26ca3ccee2268a1379eee0178c751da4b463cece90bd79e83ef9dae'
#360天眼流量传感器
webhook='https://oapi.dingtalk.com/robot/send?access_token=33b714174934a88ee3fc7de16b138c4566fd15d2d982e3ab0282d7c5f288ba03'
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
    #print data
    items= data["data"]["list"]
    #print items
    #print len(items)
    compare_time1=datetime.datetime.strptime(str(items[i]["detect_time"]), "%Y-%m-%d %H:%M:%S")
    compare_time=time.mktime(compare_time1.timetuple())

    all_data_tmp=[]

    #print str(compare_time)+'--'+str(run_time)
    while int(compare_time)>int(runtime):
        #print i
        #province=items[i]["province"]
        dest_ip = items[i]["victim_ip"]
        src_ip = items[i]["attack_ip"]
        #是否是内部ip
        isprivate_ip=0
        for ip1 in range(16,32):
            #print ip1
            if str(src_ip).find('172.'+str(ip1))!=-1:
                isprivate_ip = 1
                break
        if isprivate_ip==1:
            i = i + 1
            compare_time1=datetime.datetime.strptime(str(items[i]["detect_time"]), "%Y-%m-%d %H:%M:%S")
            compare_time=time.mktime(compare_time1.timetuple())
            continue
        reason = items[i]["name"]
        id=items[i]['id']
        req1=requests.get('https://172.16.2.105/skyeye/alarm/getIdsDetail?id='+str(id)+'&csrf_token=734fd1c6cdcf138f53227f5f190c92cb&r=0.2180415563382161',headers=headers,verify=False)
        detail_data = json.loads(req1.text)
        host = str(detail_data['data']["packet_data"])
        if host.find('/%3Cdiv%20class=%22pagenav%22%3E%0A%09%3Cform%20name=%22fsmformvalue%22%20action=%22?%22%20')!=-1:
            i = i + 1
            compare_time1=datetime.datetime.strptime(str(items[i]["detect_time"]), "%Y-%m-%d %H:%M:%S")
            compare_time=time.mktime(compare_time1.timetuple())
            continue
        host=host[host.find('Host:')+5:]
        host=host[:host.find('\r')]
        if len(host)>20 or host.find('.')==-1:
            host=dest_ip
        if host.find('360')!=-1:
            i = i + 1
            compare_time1 = datetime.datetime.strptime(str(items[i]["detect_time"]), "%Y-%m-%d %H:%M:%S")
            compare_time = time.mktime(compare_time1.timetuple())
            continue
        dest_port=detail_data['data']["base_info"]["dst_port"]

        #reason=reason[reason.find(' '):reason.find(' 攻击')].replace(' ','')
        reason=reason.replace(' ','')
        #print reason
        now_time = items[i]["detect_time"]
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
        compare_time1=datetime.datetime.strptime(str(items[i]["detect_time"]), "%Y-%m-%d %H:%M:%S")
        compare_time = time.mktime(compare_time1.timetuple())


    all_data_tmp=compare_data(all_data_tmp)

    for j in range(0,len(all_data_tmp))[::-1]:
        #print '发现攻击'
        #print '.'
        message1= '时间：' +all_data_tmp[j]["time"]+all_data_tmp[j]["data"]+' 攻击方式：' +all_data_tmp[j]["reason"]+' 攻击次数：' +str(all_data_tmp[j]["num"])+' 发现系统：360天眼流量传感器'
        #日期	时间	攻击源IP	攻击源城市	攻击次数	目的IP	目的端口	目的系统名称	攻击手法	发现设备
        message2= all_data_tmp[j]["time"]+' '+str(all_data_tmp[j]["excel1"])+' '+str(all_data_tmp[j]["num"])+' '+str(all_data_tmp[j]["excel2"]) +' '+all_data_tmp[j]["reason"]+' 360天眼流量传感器'
        #message2是导出报表格式，请把message1禁用
        time_excel=datetime.datetime.strptime(all_data_tmp[j]["time"], "%Y-%m-%d %H:%M:%S")
        time_excel2=str(time_excel.month)+'.'+str(time_excel.day)+' '+str(time_excel.hour)+':'+str(time_excel.minute)
        #print str(message2).replace(all_data_tmp[j]["time"],time_excel2)
        with open('360skyeye.txt', 'a+') as f:
            f.write(str(message2).replace(all_data_tmp[j]["time"],time_excel2)+'\n')
        #message1是普通播报
        print message1
        #xiaoding.send_text(msg=message1, is_at_all=False)

    compare_time2=datetime.datetime.strptime(str(items[0]["detect_time"]), "%Y-%m-%d %H:%M:%S")
    compare_time3=time.mktime(compare_time2.timetuple())
    runtime = int(compare_time3)
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
pagesize=50
run_time2 = time.mktime(run_time1.timetuple())
run_time=int(run_time2)
#run_time=int(time.time())
i=1
temp_d1 = datetime.datetime.fromtimestamp(run_time)
with open('360skyeye.txt', 'a+') as f:
    f.write('本次发现攻击开始时间：'+temp_d1.strftime("%Y-%m-%d %H:%M:%S")+'\n')
while True:
    #print '第'+str(i)+'次：'+str(datetime.datetime.now())
    headers = {
        'Cookie': 'session=b966108a-b599-49bd-a7da-e72c445bfb7b',
    }
    i=i+1
    try:
        dt_now = datetime.datetime.now()
        dt_before = dt_now + datetime.timedelta(days=-1)
        url = 'https://172.16.2.105/skyeye/alarm/getIdsAlert?starttime=' + dt_before.strftime(
            "%Y-%m-%d %H:%M:%S") + '&endtime=' + dt_now.strftime(
            "%Y-%m-%d %H:%M:%S") + '&victim=&attacker=&level=1,2,3,4&attack_res=0,1,2&vuln_type=网络欺骗,端口扫描,溢出攻击,拒绝服务,代码执行,信息泄露,黑市工具,SQL注入,网络钓鱼,恶意广告,暴力猜解,间谍软件,后门程序,浏览器劫持,键盘记录,窃密木马,僵尸网络,网络蠕虫,电子邮件,电脑病毒,协议异常,其他&rule_name=&page=1&pagesize='+str(pagesize)+'&order_by=alarm_time:0&csrf_token=734fd1c6cdcf138f53227f5f190c92cb&r=0.9620224037339276'
        # print url
        run_time = print_attack(run_time, url,headers)
        print '. ',
        # run_time=int(time.time())
        time.sleep(30)
    except e:
        print e.message

