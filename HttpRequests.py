# -*- coding: utf-8 -*-
"""
@Description:base object, include the base post and get method.
@Author: 006435
"""

import requests


class HttpRequests(object):
    """
    common class， please do not call it directly in robot case!
    Use it in python function with writing kws
    """
    session = requests.Session()
    ROBOT_LIBRARY_SCOPE = 'GLOBAL'

    def common_session_post(self, url, data=None, **kwargs):
        """
        @summary: 通用的session post方法，其余方法统一调用这个post方法，不再单独使用
        :param：参考requests里面post方法参数
        :return：成功之后，返回内容
        """
        print u"***python*** URL : %s" % url
        print u"***python*** post data: %s" % data
        if kwargs:
            print u"***python*** dic param: %s" % kwargs
        try:
            res = self.session.post(url, data=data, **kwargs)
            # print u"***Python*** content: ", res.content
        except Exception as e:
            raise AssertionError(u"服务器没有响应，url：%s。错误信息：%s" % (url, e))
        if res.status_code == 200 or res.status_code == 302:
            print u"***python*** response: %s" % res
            return res
        else:
            print u"服务器没有返回正常页面：url：%s。错误码：%s" % (url, res.status_code)
            return False

    def common_session_get(self, url, **kwargs):
        """
        @summary: 通用的session post方法，其余方法统一调用这个post方法，不再单独使用
        :param：参考requests里面get法参数
        :return：成功之后，返回内容
        """
        print "***python*** URL is: %s" % url
        try:
            res = self.session.get(url, **kwargs)
            # print u"***Python*** content: ", res.content
        except Exception as e:
            raise AssertionError(u"服务器没有响应，url：%s错误信息：%s" % (url, e))
        if res.status_code == 200 or res.status_code == 302:
            print u"***python*** return information: %s" % res
            return res
        else:
            print u"服务器没有返回正常页面：url：%s。错误码：%s" % (url, res.status_code)
            return False

if __name__ == '__main__':
    my_lib = HttpRequests()
