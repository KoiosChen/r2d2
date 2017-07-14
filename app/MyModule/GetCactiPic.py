# -*- coding:utf-8 -*-
# Created on 02/20/2017
# By Peter Chen
# coding=utf-8

from .GetConfig import get_config
import urllib
from urllib import request, parse
import http
import datetime
import random
from ..models import CACTI_PIC_FOLDER


def get_cacti_pic(action, **kwargs):
    """

    :param action: 'cacti_view_pic_url', ...  which stored in table api_configure
    :param kwargs: according to the action params, for exmaple: graph_id, rra_id. All of theses params' type is string.
    :return: none
    """

    params = get_config(kwargs.get('db_info'))

    filename = datetime.datetime.now().strftime('%Y%m%d%H%M%S') + str(random.randint(1, 20)) + '.png'

    filename_with_prefix = CACTI_PIC_FOLDER + filename

    if action == 'cacti_view_pic_url':
        graph_id = kwargs.get('graph_id')
        rra_id = kwargs.get('rra_id')

        pic_url = params[action] + "&local_graph_id=" + str(graph_id) + "&rra_id=" + str(rra_id)

    cookiejar = http.cookiejar.CookieJar()
    urlOpener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookiejar),
                                            urllib.request.HTTPHandler)
    urllib.request.install_opener(urlOpener)

    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0',
               'Referer': params['headers']}

    values = {'action': 'login', 'login_username': params['login_username'], 'login_password': params['login_password']}

    # login
    data = urllib.parse.urlencode(values, encoding='utf-8').encode('utf-8')
    req = urllib.request.Request(params['login_url'], data, headers)
    urllib.request.urlopen(req)

    # get pic
    req_monitor = urllib.request.Request(pic_url, None, headers)
    response2 = urllib.request.urlopen(req_monitor)

    img_response = response2.read()

    file_object = open(filename_with_prefix, 'wb')
    file_object.write(img_response)
    file_object.close()

    return params['return_pic_url'] + "/show_image/" + filename


if __name__ == '__main__':
    get_cacti_pic('86', '5')