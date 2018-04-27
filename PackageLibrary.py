# -*- coding: utf-8 -*-
"""
@Descripriotn:this is for system scan, uninstall, install
@Author: zhoufuping
"""
import os
import re
import time
from CommonMethod import add_logs_and_check_result
from CommonMethod import add_logs_for_functions


class PackageLibrary(object):
    """
    @summary:安装包管理类，实现安装包的扫描、拷贝、卸载、安装等操作.
    """

    def __init__(self, ci_addr="10.10.17.49", ci_user="root", ci_passwd="passw0rd"):
        self.ci_addr = ci_addr
        self.ci_user = ci_user
        self.ci_passwd = ci_passwd
        from SSHLibrary import SSHLibrary
        self.sshLib = SSHLibrary()

    @add_logs_for_functions
    def execute_command_and_verify_results(self, command):
        command_list = command.split(";")
        for item in command_list:
            print "execute command: {0}".format(item)
        out, error = self.sshLib.execute_command(command, True, True)
        if out:
            print "@@@@@@@@output start:@@@@@@@@@@ \n  {0} \n@@@@@@@@@output ends@@@@@@".format(out)
        if error:
            print error
            # raise AssertionError("execute command: {0} failed".format(command))
        else:
            return out

    def ssh_login(self, server_ip, username, passwd):
        print "***python*** start login server:{0}".format(server_ip)
        self.sshLib.open_connection(server_ip, server_ip, timeout='3 minute')
        content = self.sshLib.login(username, passwd, delay='3 seconds')
        print content
        if "Last login" not in content:
            if '#' not in content:
                raise AssertionError("Fail to login host {0}".format(server_ip))

    def _write(self, command):
        print "***python*** writing command or text to the terminal: {0}".format(command)
        return self.sshLib.write(command)
        
    @add_logs_for_functions
    def write_cmd(self, command):
        print "***python*** writing command or text to the terminal: {0}".format(command)
        return self.sshLib.write(command)

    @add_logs_for_functions
    def check_packages_is_update(self, mount_path, log_path):
        """
        @summary:检查安装包更新通用方法
        :param mount_path:成果管理处自动编译结果挂载点
        :param log_path:存放日志的路径
        :return:有更新返回True，没有更新返回False
        """
        history_number = []
        with open(log_path, "r+") as fp:
            read_data = fp.readlines()
            for date in read_data:
                history_number = history_number + date.split()

        print "history version:", history_number
        history_number.sort()
        self.ssh_login(self.ci_addr, self.ci_user, self.ci_passwd)

        # while True:
        latest_number = []
        output = self.execute_command_and_verify_results("ls %s" % mount_path)
        for item in output.split():
            # print item
            temp_version = filter(str.isdigit, item.encode('utf8'))
            if temp_version is not None and temp_version != '':
                latest_number.append(int(temp_version))
        print "latest version:", latest_number
        latest_number.sort()
        if latest_number:
            print "latest: {0}, compile history:{1}".format(latest_number[-1], history_number[-1])
            if int(latest_number[-1]) > int(history_number[-1]):
                # with open(log_path, "r+") as fp:
                #     print "open {0} and write value {1}".format(log_path, latest_number[-1])
                #     fp.seek(0, 2)
                #     fp.write("  " + str(latest_number[-1]))
                return latest_number[-1]
        return False

    @add_logs_and_check_result
    def check_building_status(self, mount_path, log_path):
        """
        检查是否编译成功
        :param mount_path: 成果管理处自动编译结果挂载点
        :param log_path: 存放日志的路径
        :return:True/False
        """
        building_number = self.check_packages_is_update(mount_path, log_path)
        if not building_number:
            return False
        else:
            building_number = str(building_number)
        sub_dir = building_number[:8] + '-' + building_number[8:]
        build_scene_path = '{0}/{1}/build_scene.log'.format(mount_path, sub_dir)
        with open(log_path, "r+") as fp:
            fp.seek(0, 2)
            fp.write("  " + str(building_number))
        with open(build_scene_path, "r") as rfp:
            rfp.seek(-50, 2)
            for lines in rfp.readlines():
                print lines
                if 'successfully' in lines:
                    cp_cmd = 'cp {0}/{1}/result.txt case.html'.format(mount_path, sub_dir)
                    os.system(cp_cmd)
                    # os.system("sed -i 's/代码路径/<p\/>代码路径/g' case.html")
                    os.system("sed -i 's/tmp/128.255.125.71/g' case.html")
                    return True
        return False

    @add_logs_for_functions
    def _check_packages_update_status_common(self, mount_path, ci_local_package_path, log_path):
        """
        @summary:检查安装包更新通用方法
        :param mount_path:成果管理处自动编译结果挂载点
        :param ci_local_package_path:ci服务器上存放更新的包路径
        :param log_path:存放日志的路径
        :return:有更新返回True，没有更新返回False
        """
        rtn = False
        latest_number = self.check_packages_is_update(mount_path, log_path)
        if latest_number:
            # sas相关操作
            if 'sas' in ci_local_package_path:
                self.execute_command_and_verify_results("rm -rf {0}/*".format(ci_local_package_path))
                cp_cmd = 'cp %s/SERVER_%s/*.sh %s;ls -l %s' % (mount_path, str(latest_number),
                                                               ci_local_package_path, ci_local_package_path)
                info = self.execute_command_and_verify_results(cp_cmd)
                if 'sas' in info:
                    with open(log_path, "r+") as fp:
                        print "open {0} and write value {1}".format(log_path, latest_number)
                        fp.seek(0, 2)
                        fp.write("  " + str(latest_number))
                    rtn = True
            # v3r2c01操作
            else:
                self.execute_command_and_verify_results("rm -rf {0}/*".format(ci_local_package_path))
                # 需要将日期时间戳处理成为目录
                number_str = str(latest_number)
                sub_dir = number_str[:8] + '-' + number_str[8:]
                cp_all_cmd = 'cp %s/%s/Maipu-AASV4-CMPPortal*.sh %s;ls %s' % (mount_path, sub_dir,
                                                                              ci_local_package_path,
                                                                              ci_local_package_path)
                cmp_info = self.execute_command_and_verify_results(cp_all_cmd)
                print cmp_info
                if 'Maipu' in cmp_info:
                    with open(log_path, "r+") as fp:
                        print "open {0} and write value {1}".format(log_path, latest_number)
                        fp.seek(0, 2)
                        fp.write("  " + str(latest_number))
                    rtn = True
        else:
            print "The latest build number{0} has recorded in installation log, " \
                  "enter the next loop scanning".format(str(latest_number))
        self.sshLib.close_all_connections()
        return rtn

    @add_logs_for_functions
    def check_muti_packages_update(self, check_update_status_arg_list):
        """
        :summary:同时检查多个包的更新状态
        :param check_update_status_arg_list:更新包状态参数列表，将多个包检查参数组装成为一个list，每个元素
        :为_check_packages_update_status_common方法中参数的一个字典,字典的key分别为mount_path,ci_local_package_path,log_path
        ：如：[{"字典的key分别为mount_path":"xxx","ci_local_package_path":"xxx","log_path":"xxx"}]
        :return:无返回值，出错抛出异常
        """
        check_result = False
        for arg in check_update_status_arg_list:
            if self._check_packages_update_status_common(arg["mount_path"], arg["ci_local_package_path"],
                                                         arg["log_path"]):
                check_result = True
                continue
        if not check_result:
            raise AssertionError(u"未检测到更新的软件包")

    @add_logs_for_functions
    def _copy_pacakges_to_target_srever(self, ci_local_package_path, target_server, target_username,
                                        target_passwd,  target_path):
        """
        :summary: 拷贝软件包到指定路径
        :param ci_local_package_path: ci服务器本地存放包的路径
        :param target_server: 目标服务器的地址
        :param target_username: 目标服务器的用户名
        :param target_passwd: 目标服务器的渺茫
        :param target_path: 目标服务器的存放包的路径
        :return:返回None
        """
        self.ssh_login(target_server, target_username, target_passwd)
        self.sshLib.set_client_configuration(prompt="#", timeout="10 minute")
        self.execute_command_and_verify_results("rm -rf {0}/*".format(target_path))  # empty the old package
        # self.execute_command_and_verify_results("mkdir {0}".format(om_server_package_path))  # empty the old package
        self._write(
            "scp -r {0}@{1}:{2}/* {3}".format(self.ci_user, self.ci_addr, ci_local_package_path, target_path))
        output = self.sshLib.read(delay="10s")
        print output

        if "yes" in output:
            print "yes/no"
            self.sshLib.write('yes')
            print '-------===================----------'
            time.sleep(2)
            self.sshLib.write(self.ci_passwd)
            print self.sshLib.read_until_prompt("DEBUG")
        elif "assword" in output:
            print "enter your password"
            self.sshLib.write(self.ci_passwd)
            print '------------------------------------'
            print self.sshLib.read_until_prompt("DEBUG")
        elif '#' in output[-10:]:
            print '===================================='       
        else:
            print '++++++++++++++++++++++++++++++'
            print self.sshLib.read_until_prompt("DEBUG")
            print '++++++++++++++++++++++++++++++'
        self.sshLib.close_all_connections()

    @add_logs_for_functions
    def copy_to_muti_target_server(self, copy_package_arg_list):
        """
        :拷贝软件包到多个服务器的指定目录
        :param copy_package_arg_list:_copy_pacakges_to_target_srever方法的参数的为元素组成的一个list
        :return:
        """
        for arg in copy_package_arg_list:
            if len(arg.keys()) == 5:
                for key in arg.keys():
                    if key not in ["ci_local_package_path", "target_server", "target_username", "target_passwd",
                                   "target_path"]:
                        raise AssertionError(u"copy_package_arg_list中的参数的key %s 不正确" % str(key))
            else:
                raise AssertionError(u"copy_package_arg_list中的参数的键值对个数不正确")
        for arg in copy_package_arg_list:
            self._copy_pacakges_to_target_srever(arg["ci_local_package_path"], arg["target_server"],
                                                 arg["target_username"], arg["target_passwd"], arg["target_path"])

    @add_logs_for_functions
    def _common_install_param_input(self, install_param):
        """
        :summary:通用安装参数匹配输入方法
        :param install_param: 安装参数，为空表示不需要任何手工输入的参数，否则以[("regexp1","input1"),("regexp2","input2")]
        这种形式传入参数
        :return:无返回，执行出错抛出异常
        """
        if install_param:
            for regexp, input_ in install_param:
                print regexp, input_
                print self.sshLib.read_until(regexp)
                print self.sshLib.write(input_)
            print self.sshLib.read_until_regexp(".*#$", "DEBUG")
        else:
            print self.sshLib.read_until_regexp(".*#$", "DEBUG")
    
    @add_logs_for_functions
    def send_cmd_by_expect(self, cmd_param):
        """
        :summary:根据顺序匹配输入命令
        :param cmd_param: 安装参数，为空表示不需要任何手工输入的参数，否则以[("regexp1","input1"),("regexp2","input2")]这种形式传入参数
        :return:无返回，执行出错抛出异常
        """
        if cmd_param:
            for regexp, input_ in cmd_param:
                print regexp, input_
                print self.sshLib.read_until(regexp)
                print self.sshLib.write(input_)
            print self.sshLib.read_until_regexp(".*#$", "DEBUG")
        else:
            print self.sshLib.read_until_regexp(".*#$", "DEBUG")
            
    @add_logs_for_functions
    def _install_pkg_common(self, target_server, target_username, target_passwd, pkg_path, app_name, shell_args):
        """
        :summary: 安装包通用方法
        :param target_server: 安装包的目标服务器地址
        :param target_username: 安装包的目标服务器用户名
        :param target_passwd: 安装包的目标服务器的密码
        :param pkg_path: 安装包在目标服务器的路径
        :param app_name: 组件名称
        :return:成功返回True，否则抛出异常
        """
        self.ssh_login(target_server, target_username, target_passwd)
        self.sshLib.set_client_configuration(prompt="#", timeout="15 minute")
        # self.check_command_results("service srvmgt stop")
        get_package_cmd = "cd {0};chmod 444 *;pwd;ll |grep {1}".format(pkg_path, app_name)
        self._write(get_package_cmd)
        output = self.sshLib.read_until_prompt("DEBUG")
        print output
        pattern = "(\S+.sh)"
        m = re.search(pattern, output)
        if m:
            pkg_name = m.group(1)
            install_command = "cd %s;pwd;ls;sh %s %s" % (pkg_path, pkg_name, shell_args)
        else:
            raise AssertionError(u"未匹配到正确的安装包")
        print self.sshLib.write(install_command)
        info = ''
        last_info = ''
        repeat_time = 1
        while True:
            temp = self.sshLib.read(delay='10s')
            print temp
            info += temp
            if 'Confirm install [y/n]?' in info:
                print self.sshLib.write('y')
                info = ''
                continue
            if 'Confirm install [Y/n]?' in info:
                print self.sshLib.write('y')
                info = ''
                continue
            if 'Confirm install? [Y/n]' in info:
                print self.sshLib.write('y')
                info = ''
                continue
            if 'Confirm uninstall old ver [y/n]?' in info:
                print self.sshLib.write('y')
                info = ''
                continue
            if 'Input setup dest path: [/opt/mpup]' in info:
                print self.sshLib.write('')
                info = ''
                continue
            if 'Input setup dest path: [/home/mpup/mpup]' in info:
                print self.sshLib.write('')
                info = ''
                continue
            if 'please confirm enable Maipu Security (y/n)?' in info:
                print self.sshLib.write('n')
                info = ''
                continue
            if 'Confirm continue [y/n]?' in info:
                print self.sshLib.write('y')
                info = ''
                continue
            if re.search(':~/\w+ #', info):
                return True
            if repeat_time < 150:
                if last_info == temp:
                    repeat_time += 1
                else:
                    repeat_time = 1
                    last_info = temp
            else:
                print info
                raise AssertionError(u'已经连续150次,1500s相同输出了，please check!')

    @add_logs_for_functions
    def install_muti_package(self, install_package_args):
        """
        :批量安装多个安装包
        :param install_package_args:安装多个APP的参数列表：列表中每个元素为字典，字典的键为_install_pkg_common方法
        :的参数名，如：[{"target_server":"xx","target_user_name":"xx","target_passwd":"x","pkg_path","xx","app":"xx"
        :"install_param":[install_param]}]
        :return:无返回值，出错抛出异常
        """
        for arg in install_package_args:
            self._install_pkg_common(arg["target_server"], arg["target_username"], arg["target_passwd"],
                                     arg["pkg_path"], arg["app_name"], arg["shell_args"])

    @add_logs_for_functions
    def _uninstall_pacakge_common(self, target_server, target_username, target_passwd):
        """
        :summary:卸载安装包通用方法
        :param target_server:卸载包的目标服务器地址
        :param target_username:卸载包的目标服务器用户名
        :param target_passwd:卸载包的目标服务器密码
        :return:
        """
        self.ssh_login(target_server, target_username, target_passwd)
        self.sshLib.set_client_configuration(prompt="#", timeout="20 minute")
        self._write('/opt/mpup/bin/mpsetup show')
        output = self.sshLib.read_until_prompt("DEBUG")
        service_list = output.split('\n')
        for service in service_list[:-1]:  # 会将最后的匹配算进去，这个去除掉
            print 'current info is %s' % service
            m = re.search('\s+(\w+.*?)\s', service)
            if not m:
                print "dot not match any sercice"
                return True
            print 'service is %s' % m.group(1)
            if 'MPUP' in m.group(1):
                continue
            self._write('/opt/mpup/bin/mpsetup uninstall ' + m.group(1))
            # self._write('mpsetup uninstall ' + m.group(1))
            output = self.sshLib.read_until_prompt("DEBUG")
            print output
        # uninstall mpup mpupcore
        self._write('/opt/mpup/bin/mpsetup uninstall MPUPCore')
        # self._write('mpsetup uninstall MPUPCore')
        output = self.sshLib.read_until_prompt("DEBUG")
        print output
        self._write('/opt/mpup/bin/mpsetup uninstall MPUP')
        # self._write('mpsetup uninstall MPUP')
        output = self.sshLib.read_until_prompt("DEBUG")
        print output
        self.sshLib.close_all_connections()
        return True

    @add_logs_for_functions
    def uninstall_muti_packages(self, pkg_uninstall_arg):
        """
        :批量卸载多个app的通用方法
        :param pkg_uninstall_arg:卸载多个APP的卸载参数列表：列表中每个元素为字典，字典的键为_uninstall_pacakge_common方法
        :的参数名，如：[{"target_server":"xx","target_user_name":"xx","target_passwd":"x","pkg_path","xx","app":"xx"}]
        :return:无返回值，出错抛出异常
        """
        for arg in pkg_uninstall_arg:
            if len(arg.keys()) == 3:
                for key in arg.keys():
                    if key not in ["target_server", "target_username", "target_passwd"]:
                        raise AssertionError(u"pkg_uninstall_arg中的参数的key %s 不正确" % str(key))
            else:
                raise AssertionError(u"pkg_uninstall_arg中的参数的键值对个数不正确")
        for arg in pkg_uninstall_arg:
            self._uninstall_pacakge_common(arg["target_server"], arg["target_username"], arg["target_passwd"])

    @add_logs_for_functions
    def use_install_package_uninstall(self, pkg_uninstall_arg):
        """
        用安装包卸载程序
        :param pkg_uninstall_arg:
        :return:
        """
        for arg in pkg_uninstall_arg:
            self.ssh_login(arg["target_server"], arg["target_username"], arg["target_passwd"])
            self.sshLib.set_client_configuration(prompt="#", timeout="15 minute")
            self.sshLib.execute_command('service srvmgt stop')
            get_package_cmd = "cd {0};chmod 444 *;pwd;ll |grep {1}".format(arg["pkg_path"], arg["app_name"])
            self._write(get_package_cmd)
            output = self.sshLib.read_until_prompt("DEBUG")
            print output
            pattern = "(\S+.sh)"
            m = re.search(pattern, output)
            if m:
                pkg_name = m.group(1)
                uninstall_command = "cd %s;pwd;ls;sh %s uninstall" % (arg["pkg_path"], pkg_name)
            else:
                raise AssertionError(u"未匹配到正确的安装包")
            print self.sshLib.write(uninstall_command)
            info = ''
            last_info = ''
            repeat_time = 1
            while True:
                temp = self.sshLib.read(delay='10s')
                print temp
                info += temp
                if 'Confirm uninstall all installed files and datas [y/n]?' in info:
                    print self.sshLib.write('y')
                    info = ''
                    continue
                # 匹配结束
                if re.search(':~/\w+ #', info):
                    break
                # 匹配长期暂停
                if repeat_time < 100:
                    if last_info == temp:
                        repeat_time += 1
                    else:
                        repeat_time = 1
                        last_info = temp
                else:
                    print info
                    raise AssertionError(u'已经连续100次,1000s相同输出了，please check!')

    @add_logs_and_check_result
    def init_system(self, target_server, target_username, target_passwd, init_command_dict_list):
        """
        初始化系统
        :param target_server:服务器地址
        :param target_username:用户
        :param target_passwd:密码
        :param init_command_dict_list:初始化参数字典列表
        :return:True/False
        """
        self.ssh_login(target_server, target_username, target_passwd)
        self.sshLib.set_client_configuration(prompt="#", timeout="10 minute")
        self._write('service srvmgt init')
        info = ''
        last_info = ''
        repeat_time = 1
        while True:
            temp = self.sshLib.read(delay='10s')
            print temp
            info += temp
            for command_dict in init_command_dict_list:
                if command_dict[0] in info:
                    print self.sshLib.write(command_dict[1])
                    init_command_dict_list.remove(command_dict)
                    info = ''
                    break
            else:
                # 这里是运行结束
                if re.search(':~.*?#', info):
                    return True
                # 这里判断重复次数
                if repeat_time < 40:
                    if last_info == temp:
                        repeat_time += 1
                    else:
                        repeat_time = 1
                        last_info = temp
                else:
                    print info
                    print u'已经连续40次,400s相同输出了，please check!'
                    return False

    @add_logs_and_check_result
    def check_file_is_change(self, file_path, limit_time):
        """
        判断目标文件是否在限制时间内有更改
        :param file_path:目标文件
        :param limit_time:限制时间，秒为单位，一个小时为3600秒
        :return:
        """
        self.ssh_login(self.ci_addr, self.ci_user, self.ci_passwd)
        output = self.execute_command_and_verify_results('stat -c %Y ' + file_path + """ |awk '{printf  $0" "; 
        system("date +%s")}'|awk '{print $2-$1}'""")
        if int(output) > int(limit_time):
            return False
        return True

if __name__ == "__main__":
    myLib = PackageLibrary()
    running_case_para = {
        'OM_ADDR': '129.255.146.119',
        'OM_ADDR_PORT': '129.255.146.119:8080',
        'WEMP_ADDR': '129.255.146.119',
        'WEMP_ADDR_PORT': "129.255.146.119:7010"
    }
    mpha_init_master_command_list = [
        ("""Please input the index of the eth interface for service (0 - 1)""", "0"),
        ("""IP Address :""", "10.10.9.215"),
        ("""IP Mask :""", "255.255.0.0"),
        ("""Default Gateway:""", "10.10.9.254"),
        ("""Host Domain :""", "cn_v3r2c03"),
        ("""Start mpsecsrv?""", "n"),
        ("""HA? (y/n)""", "n"),
        ("""Configure FTP Server?  ( y/n )""", "n"),
        ("""Configure application servers? (y/n)""", "y"),
        ("""Please input node address list(if more than one, please use the space division)""", "127.0.0.1"),
        ("""please confirm customer system asscess business[y/n]?""", "y"),
        ("""please confirm customer system feature cached[y/n]?""", "y"),
        ("""please input customer system access url:""", ""),
        ("""please input customer system access password:""", "")]
