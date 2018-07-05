# -*- coding: utf-8 -*-
# flake8: noqa
import requests

from qiniu import Auth
import qiniu.config

access_key = 'Be5ogmeOQsxk0bdcKmBZq_gypqsm0aI8FXuUwouo'
secret_key = 'YtC_LY6xlHH_zc6dl0dPIHtE_K6BWVg5v'
q = Auth(access_key, secret_key)
#有两种方式构造base_url的形式
base_url = 'http://%s/%s' % ('pb11dyv3t.bkt.clouddn.com', 'my-python-logo.png')
#或者直接输入url的方式下载
#base_url = 'http://domain/key'
#可以设置token过期时间
private_url = q.private_download_url(base_url, expires=3600)
print(private_url)
r = requests.get(private_url)
#assert r.status_code == 200