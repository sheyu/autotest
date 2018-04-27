# -*- coding: utf-8 -*-
"""
@Description:common methods
@Author: 006435
"""
import json
import functools
from time import strftime, localtime


def handle_func_doc(func):
    """
    处理函数的文档说明,将函数的参数整理到文档说明中
    :param func: 函数
    :return:整理后的参数和文档说明
    """
    func_arg = list(func.func_code.co_varnames[:func.func_code.co_argcount][::-1])
    if func_arg[-1] == 'self':
        func_arg.pop()
    arg = []
    if func.func_defaults is not None:
        func_defaults = func.func_defaults[::-1]
        for i in range(len(func_defaults)):
            if isinstance(func_defaults[i], (int, float, type(None), list, tuple)):
                temp = str(func_defaults[i])
            elif isinstance(func_defaults[i], unicode):
                temp = '"' + func_defaults[i].encode("utf-8") + '"'
            else:
                temp = '"' + func_defaults[i] + '"'
            arg.append(func_arg[i] + "=" + temp)
        arg += list(func_arg[len(func_defaults):])
    else:
        arg = func_arg
    arg = arg[::-1]
    if func.__doc__ is not None:
        func.__doc__ = "参数列表: [" + ", ".join(arg) + "]   功能：" + func.__doc__.strip()
    else:
        func.__doc__ = "参数列表: [" + ", ".join(arg) + "]"


def running_func(func, *arg, **kwargs):
    """
    运行函数，并作参数处理
    :param func:
    :param arg:
    :param kwargs:
    :return:func result
    """
    print u'╔╦╦╦╦╦╦╦╦╦╦╦ enter function: 【%s】 time:%s ╦╦╦╦╦╦╦╦╦╦╦╗'\
          % (func.__name__, strftime("%H:%M:%S", localtime()))
    print u'║==function args is ', arg
    print u'║==function kwargs is ', kwargs
    arg_list = []
    for item in arg:
        if isinstance(item, unicode):
            item = item.encode('utf-8')
        arg_list.append(item)
    arg = tuple(arg_list)
    for item in kwargs:
        if isinstance(kwargs[item], unicode):
            kwargs[item] = kwargs[item].encode('utf-8')
    return_value = func(*arg, **kwargs)
    print u'║==function return value is ', return_value
    print u'╚╩╩╩╩╩╩╩╩╩╩╩ exit function: 【%s】 time:%s  ╩╩╩╩╩╩╩╩╩╩╩╝'\
          % (func.__name__, strftime("%H:%M:%S", localtime()))
    return return_value


def add_logs_and_check_result(func):
    """
    @summary: 函数装饰器，给函数标记上时间,并判断返回值
    """
    handle_func_doc(func)

    @functools.wraps(func)
    def wrapper(*arg, **kwargs):
        # 判断是否关心返回值(引用方式为 flag=false)
        check_flag = True
        if kwargs.get('flag', 'true').lower() == 'false':
            check_flag = False
            kwargs.pop('flag')
        # 判断值为错误，如果为正确直接异常(引用方式为 ret=false)
        check_ret = True
        if kwargs.get('ret', 'true').lower() == 'false':
            check_ret = False
            kwargs.pop('ret')
        return_value = running_func(func, *arg, **kwargs)
        # 判断是否当前结果为False， ret=false 表示返回值必须是False
        if not check_ret:
            if return_value:
                raise AssertionError('Result is not correct, expect false but true!')
            else:
                return True
        # 判断是否关心返回值，check_flag = False 表示不关心
        if (not check_flag) or return_value:
            return return_value
        else:
            raise AssertionError('Result is not correct, expect true but false!')
    return wrapper


def add_logs_for_functions(func):
    """
    @summary: 函数装饰器，给函数标记上时间
    """
    handle_func_doc(func)

    @functools.wraps(func)
    def wrapper(*arg, **kwargs):
        return running_func(func, *arg, **kwargs)
    return wrapper


def get_value_from_response_content(response, key="", msg=None):
    """
    @summary: 获取返回值里面指定字段的内容
    :param:response:页面返回值，
    :param:key：需要获取内容key值
    :param:msg:打印消息，并根据这个值是否判断结果
    :return:制定字段内容
    """
    assert isinstance(response.content, object)
    try:
        content = json.loads(response.content)
        print "***Python*** response content:%s" % content
    except Exception as e:
        print "***python***", e
        if key:
            return False
        else:
            return response.content
    if key:
        if key in content:
            print u"key:%s, value:%s" % (key, content[key])
            return_value = content[key]
            if msg is not None:
                if return_value:
                    print msg, u'成功！'
                    return return_value
                else:
                    print msg, u'失败！'
                    return return_value
            return return_value
        else:
            raise AssertionError("There is no key in content:%s" % content)
    else:
        return content


def common_query_result_resolve(query_resp, query_item=None, return_key=None, all_query_flag=False, precise_query=True):
    """
    通用查询后的结果处理
    :param query_resp: 查询结果的resp
    :param query_item: 精确查询时的要用的键值对,默认为None.传参形式（name:xxx   name为data中的key值，xxx为value）
    :param return_key: 需要返回的key
    :param all_query_flag: 全部查询标志，默认为False，当为True时返回所有值
    :param precise_query: 精确查询标记，默认为True
    :return: 需要返回的值
    """
    data = get_value_from_response_content(query_resp, 'data')
    if not data:
        return False
    if not isinstance(data, list):
        return False
    # 若flag为True，直接返回全部数据
    if all_query_flag:
        return data
    else:
        # 是否精确查询
        if precise_query and query_item:
            _key, value = query_item.split(':')
            if isinstance(value, unicode):
                value = value.encode('utf-8')
            for item in data:
                if isinstance(item[_key], unicode):
                    item_value = str(item[_key].encode('utf-8'))
                else:
                    item_value = str(item[_key])
                if item_value == value:
                    return_data = item
                    break
            else:
                return False
        else:
            return_data = data[0]
        # 是否需要返回特定的key值
        if return_key:
            return return_data[return_key]
        else:
            return return_data


def assemble_dict_with_param_str(target_dict, param_str):
    """
    根据参数str整合参数字典
    :param target_dict:需要更新的字典
    :param param_str: 参数字符串（xxkey:xxvalue     xxkey1:xxvalue;xxkey2:xxvalue   xxkey1:xxvalue|xxkey2:xxvalue）
    :return:target_dict
    """
    if not param_str:
        return target_dict
    key_value_list = []
    if '|' in param_str:
        key_value_list = param_str.split('|')
    elif ';' in param_str:
        key_value_list = param_str.split(';')
    if key_value_list:
        for key_value in key_value_list:
            key_, value = key_value.split(':')
            target_dict[key_] = value
    else:
        key_, value = param_str.split(':')
        target_dict[key_] = value
    return target_dict
