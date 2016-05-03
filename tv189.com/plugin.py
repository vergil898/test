#!/usr/bin/env python
#-*- coding: UTF-8 -*-

import sys
import io
import re
import pycurl
import json
import urllib
import time
import hashlib
import random
from lxml import etree


reload(sys)
sys.setdefaultencoding('utf-8')


class MyCurl(object):

    def __init__(self, **param):
        self.buf = io.BytesIO()
        self.header_buf = io.BytesIO()

        share = pycurl.CurlShare()
        #多个Curl可以共享cookie
        share.setopt(pycurl.SH_SHARE, pycurl.LOCK_DATA_COOKIE)
        share.setopt(pycurl.SH_SHARE, pycurl.LOCK_DATA_DNS)

        post_c = pycurl.Curl()
        post_c.setopt(pycurl.SHARE, share)
        post_c = self._init(post_c, param)
        post_c.setopt(pycurl.WRITEFUNCTION, self.buf.write)
        post_c.setopt(pycurl.HEADERFUNCTION, self.header_buf.write)
        self.post_c = post_c

        get_c = pycurl.Curl()
        get_c.setopt(pycurl.SHARE, share)
        get_c = self._init(get_c, param)
        get_c.setopt(pycurl.WRITEFUNCTION, self.buf.write)
        get_c.setopt(pycurl.HEADERFUNCTION, self.header_buf.write)
        self.get_c = get_c

        down_c = pycurl.Curl()
        down_c.setopt(pycurl.SHARE, share)
        down_c = self._init(down_c, param)
        down_c.setopt(pycurl.WRITEFUNCTION, self.buf.write)
        down_c.setopt(pycurl.HEADERFUNCTION, self.header_buf.write)
        self.down_c = down_c

        upload_c = pycurl.Curl()
        upload_c.setopt(pycurl.SHARE, share)
        upload_c = self._init(upload_c, param)
        upload_c.setopt(pycurl.WRITEFUNCTION, self.buf.write)
        upload_c.setopt(pycurl.HEADERFUNCTION, self.header_buf.write)
        upload_c.setopt(pycurl.TIMEOUT, 300)
        self.upload_c = upload_c

        self.param = param
        self.share = share

    def get_page(self, url, method='get', post_data=None, cookie=None, referer=None, header=''):
        self.buf.seek(0)
        self.buf.truncate()
        self.header_buf.seek(0)
        self.header_buf.truncate()

        if method == 'post':
            c = self.post_c
            c.setopt(pycurl.POSTFIELDS, post_data)
        else:
            c = self.get_c

        if cookie:
            c.setopt(pycurl.COOKIE, cookie)

        _referer = ''
        for l in self.head_list:
            name = l.split(':', 1)[0]
            if name == 'Referer':
                _referer = l
        if _referer:
            self.head_list.remove(_referer)
        if referer:
            #c.setopt(pycurl.REFERER, referer)
            self.head_list.append('Referer: ' + referer)
            c.setopt(pycurl.HTTPHEADER, self.head_list)
        else:
            c.setopt(pycurl.HTTPHEADER, self.head_list)

        if header:
            _header = list(self.head_list)
            for l in header:
                name = l.split(':', 1)[0]
                for j in self.head_list:
                    _name = j.split(':', 1)[0]
                    if name == _name:
                        _header.remove(j)
                _header.append(l)

            c.setopt(pycurl.HTTPHEADER, _header)

        c.setopt(pycurl.URL, url)
        #get_c.setopt(pycurl.PROXY, 'http://127.0.0.1:8888')
        c.perform()

        m = self.info(c)
        v = self.buf.getvalue()
        return m, v

    def down_file(self, url, file_path, mode='wb+'):

        f = open(file_path, mode)
        self.down_c.setopt(pycurl.URL, url)
        #win下不能用
        #self.down_c.setopt(pycurl.WRITEDATA, file_path)
        self.down_c.setopt(pycurl.WRITEFUNCTION, f.write)
        #self.down_c.setopt(pycurl.PROXY, 'http://127.0.0.1:8888')
        self.down_c.perform()

        f.flush()
        f.close()

    def upload_file(self, url, file, post_data=[]):

        self.buf.seek(0)
        self.buf.truncate()
        self.upload_c.setopt(pycurl.URL, url)
        self.upload_c.setopt(pycurl.POST, 1)
        self.upload_c.setopt(pycurl.WRITEFUNCTION, self.buf.write)
        allfile = []
        for l in post_data:
            allfile.append((l[0], (pycurl.FORM_CONTENTS, l[1])))
        for f in file:
            allfile.append((f[0], (pycurl.FORM_FILENAME, f[1], pycurl.FORM_FILE, f[2])))
        #self.upload_c.setopt(pycurl.PROXY, 'http://127.0.0.1:8888')
        self.upload_c.setopt(pycurl.HTTPPOST, allfile)
        self.upload_c.perform()

        m = self.info(self.upload_c)
        v = self.buf.getvalue()
        return m, v

    def get_cookie_list(self):
        return self.info(self.get_c)['cookielist']

    def info(self, handle):
        m = {}
        m['effective-url'] = handle.getinfo(pycurl.EFFECTIVE_URL)
        m['http-code'] = handle.getinfo(pycurl.HTTP_CODE)
        m['total-time'] = handle.getinfo(pycurl.TOTAL_TIME)
        m['namelookup-time'] = handle.getinfo(pycurl.NAMELOOKUP_TIME)
        m['connect-time'] = handle.getinfo(pycurl.CONNECT_TIME)
        m['pretransfer-time'] = handle.getinfo(pycurl.PRETRANSFER_TIME)
        m['redirect-time'] = handle.getinfo(pycurl.REDIRECT_TIME)
        m['redirect-count'] = handle.getinfo(pycurl.REDIRECT_COUNT)
        m['size-upload'] = handle.getinfo(pycurl.SIZE_UPLOAD)
        m['size-download'] = handle.getinfo(pycurl.SIZE_DOWNLOAD)
        m['speed-upload'] = handle.getinfo(pycurl.SPEED_UPLOAD)
        m['header-size'] = handle.getinfo(pycurl.HEADER_SIZE)
        m['request-size'] = handle.getinfo(pycurl.REQUEST_SIZE)
        m['content-length-download'] = handle.getinfo(pycurl.CONTENT_LENGTH_DOWNLOAD)
        m['content-length-upload'] = handle.getinfo(pycurl.CONTENT_LENGTH_UPLOAD)
        m['content-type'] = handle.getinfo(pycurl.CONTENT_TYPE)
        m['response-code'] = handle.getinfo(pycurl.RESPONSE_CODE)
        m['speed-download'] = handle.getinfo(pycurl.SPEED_DOWNLOAD)
        m['ssl-verifyresult'] = handle.getinfo(pycurl.SSL_VERIFYRESULT)
        m['filetime'] = handle.getinfo(pycurl.INFO_FILETIME)
        m['starttransfer-time'] = handle.getinfo(pycurl.STARTTRANSFER_TIME)
        m['redirect-time'] = handle.getinfo(pycurl.REDIRECT_TIME)
        m['redirect-count'] = handle.getinfo(pycurl.REDIRECT_COUNT)
        m['http-connectcode'] = handle.getinfo(pycurl.HTTP_CONNECTCODE)
        m['httpauth-avail'] = handle.getinfo(pycurl.HTTPAUTH_AVAIL)
        m['proxyauth-avail'] = handle.getinfo(pycurl.PROXYAUTH_AVAIL)
        m['os-errno'] = handle.getinfo(pycurl.OS_ERRNO)
        m['num-connects'] = handle.getinfo(pycurl.NUM_CONNECTS)
        m['ssl-engines'] = handle.getinfo(pycurl.SSL_ENGINES)
        m['cookielist'] = handle.getinfo(pycurl.INFO_COOKIELIST)
        m['lastsocket'] = handle.getinfo(pycurl.LASTSOCKET)
        m['ftp-entry-path'] = handle.getinfo(pycurl.FTP_ENTRY_PATH)
        return m

    def _init(self, c, param):

        #不验证证书和host
        c.setopt(pycurl.SSL_VERIFYPEER, False)
        c.setopt(pycurl.SSL_VERIFYHOST, False)

        if param.get('connect_time_out'):
            c.setopt(pycurl.CONNECTTIMEOUT, param['connect_time_out'])
        else:
            c.setopt(pycurl.CONNECTTIMEOUT, 10)

        if param.get('time_out'):
            c.setopt(pycurl.TIMEOUT, param['time_out'])
        else:
            c.setopt(pycurl.TIMEOUT, 20)

        c.setopt(pycurl.FOLLOWLOCATION, 1)
        c.setopt(pycurl.MAXREDIRS, 5)
        c.setopt(pycurl.AUTOREFERER, 1)
        c.setopt(pycurl.NOSIGNAL, 1)
        c.setopt(pycurl.DNS_CACHE_TIMEOUT, 60 * 60)

        head_list = []
        if param.get('user_agent'):
            user_agent = 'User-Agent: ' + param['user_agent']
            head_list.append(user_agent)
        else:
            head_list.append('User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0')

        if param.get('accept'):
            accept = 'Accept: ' + param['accept']
            head_list.append(accept)
        else:
            head_list.append('Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')

        if param.get('accept_language'):
            accept_language = 'Accept-Language: ' + param['accept_language']
            head_list.append(accept_language)
        else:
            head_list.append('Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3')

        if param.get('accept_encoding'):
            accept_encoding = 'Accept-Encoding: ' + param['accept_encoding']
            head_list.append(accept_encoding)

        head_list.append('Connection: keep-alive')

        if head_list:
            c.setopt(pycurl.HTTPHEADER, head_list)

        self.head_list = head_list

        if param.get('proxy_ip'):
            c.setopt(pycurl.PROXY, param['proxy_ip'])

        if param.get('cookie_file_path'):
            c.setopt(pycurl.COOKIEFILE, param['cookie_file_path'])
            c.setopt(pycurl.COOKIEJAR, param['cookie_file_path'])

        if param.get('cookie'):
            c.setopt(pycurl.COOKIE, param['cookie'])

        return c

    def header(self):
        _header = self.header_buf.getvalue()
        return self.parse_header(_header)

    def parse_header(self, header):
        header_list = header.split("\r\n")
        header_list = header_list[0:-2]
        if '' in header_list:
            blank_index = len(header_list) - 1 - (list(reversed(header_list)).index(''))
            header_list = header_list[blank_index + 1:]

        header_d = {}
        header_d['http_code'] = header_list[0].split(' ')[1]
        for l in header_list[1:]:
            _l = l.split(":")
            name = _l[0].strip()
            value = ''.join(_l[1:]).strip()
            header_d[name.lower()] = value.lower()

        return header_d

    def flush_cookie(self):
        self.get_c.setopt(pycurl.COOKIELIST, 'FLUSH')


def test(url):
    io_buf = io.BytesIO()
    d = {}
    d['hostingurl'] = url
    jn = json.dumps(d)
    io_buf.write(jn)
    io_buf.seek(0)
    sys.stdin = io_buf
    main()


def get_sign(_str, APPID, DEVID):
    APPID = 'appid=' + APPID
    DEVID = 'devid=' + DEVID
    SIGN_KEY = "CEAE537402504A32B53AE02D79A95F15"
    #year, mon, day, hour, minu, sec = ['%02d'%l for l in time.localtime()[:6]]
    date = ''.join(['%02d' % l for l in time.localtime()[:6]])
    d = 'time=' + date

    l = _str.split('&')
    l.append(APPID)
    l.append(DEVID)
    l = sorted(l)

    s = '&'.join(l) + '&' + d + '&' + SIGN_KEY
    m = hashlib.md5()
    m.update(s)
    return m.hexdigest() + '|' + date


def main():
    _input = sys.stdin.read()
    jsonCont = json.loads(_input)
    hostingurl = jsonCont.get('hostingurl')
    mc = MyCurl(cookie_file_path='cookie.txt', proxy_ip='127.0.0.1:8888')

    pid = re.search(r'/(\d+?)\.htm', hostingurl).group(1)

    _param = [
        ('username', '13732202904'),
        ('password', 'vobile123456'),
        ('remenberme', '1'),
    ]
    _param = urllib.urlencode(_param)
    url = 'http://my.tv189.com/site/loginiframe?backurl=' + urllib.quote(hostingurl) + '&ltype='
    mc.get_page(url, 'post', _param)

    url = 'http://yx.tv189.com/checkyxdetail.php?pid=' + pid + '&r=' + str(random.random())
    h, v = mc.get_page(url, referer=hostingurl)
    v = re.search(r'\((.*)\)', v, flags=re.S).group(1)
    v = json.loads(v)

    sig, time = get_sign('contentid=' + pid + '&indexid=1&uid=6429908&vodtoken=' + v['token'], v['appid'], v['devid']).split('|')
    _param = [
        ('contentid', pid),
        ('indexid', '1'),
        ('uid', '6429908'),
        ('vodtoken', v['token']),
        ('sign', sig),
        ('time', time),
        ('appid', v['appid']),
        ('devid', v['devid']),
    ]
    param = urllib.urlencode(_param)
    url = 'http://api.tv189.com/service/omsPcProgram/get_video_play_info?' + param
    h, v = mc.get_page(url)
    root = etree.fromstring(v)
    media_url = root.xpath('//url')[-1].text
    print media_url


if __name__ == '__main__':
    #test('http://yx.tv189.com/m/397123.htm')
    test('http://yx.tv189.com/v/393547.htm')
    #print get_sign('contentid=397123&indexid=1&uid=6429908&vodtoken=3f7460c8-bb9e-4306-936c-bbe6dc75cb8a')
    #main()
