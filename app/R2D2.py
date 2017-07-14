# -*- coding: utf-8 -*-
import datetime
import json
import re
import threading
import time
from collections import defaultdict
from . import db
from . import logger
from .MyModule import Snmp, AlarmPolicy, GetData, GetCactiPic, Telnet5680T, SendMail, HashContent, requestVerboseInfo
from .models import UpsInfo, PonAlarmRecord, Device, OntAccountInfo


def nesteddict():
    """
    构造一个嵌套的字典
    :return:
    """
    return defaultdict(nesteddict)


def cacti_db_monitor(db_info=None):
    db_info = db_info or 'Cacti'
    getdata = GetData.GetData(db_info=db_info)
    getdata.t.cursor.execute('set names latin1')
    catalog = ('id', 'description', 'hostname', 'status', 'status_fail_date')
    host_offline = getdata.get_result(query='host_offline', catalog=catalog)

    alarm_content = []
    for info in host_offline:
        alarm_content.append('id: ' + str(info['id']) + ' ' + info['description'] +
                             ' 于 ' + info['status_fail_date'].strftime('\'%Y-%m-%d %H:%M:%S\'') + ' 离线' +
                             ', IP: ' + info['hostname'] +'\n\n')

    catalog2 = ('id', 'name', 'thold_hi', 'thold_low', 'thold_alert', 'host_id', 'graph_id', 'rra_id')
    thold_alert = getdata.get_result(query='thold_alert', catalog=catalog2)

    for alert in thold_alert:
        pic_url = GetCactiPic.get_cacti_pic('cacti_view_pic_url',
                                            graph_id=alert['graph_id'],
                                            rra_id='5',
                                            db_info=db_info)
        alarm_content.append('id: ' + str(alert['id']) +
                             ' ' + alert['name'] +
                             '产生阀值告警。\n>>>图片链接:' + pic_url + '\n\n')

    if host_offline or thold_alert:
        try:
            AlarmPolicy.alarm(alarm_content=alarm_content, alarm_type='0')
        except Exception as e:
            logger.error(e)
    else:
        logger.info('There is no host offline or thold alert')

    db.session.expire_all()
    db.session.close()


def ups_monitor():
    ups_status = {'1': 'unknown', '2': 'online', '3': 'onBattery', '4': 'onBoost', '5': 'sleeping', '6': 'onBypass',
                  '7': 'rebooting', '8': 'standBy', '9': 'onBuck'}
    ups = Snmp.Snmp()
    ups_info = UpsInfo.query.all()
    alarm_list = []
    for u in ups_info:
        logger.debug('Getting {} {} snmp info'.format(u.name, u.ip))
        ups.destHost = u.ip
        ups.community = u.community
        snmp_result = {}
        for key, oid in json.loads(u.oid_dict).items():
            logger.debug('Get {} {}'.format(key, oid))
            ups.oid = oid
            result = ups.query()
            try:
                result_value = re.findall(r'=\s+(\d+)', str(result[0]))[0]
                logger.debug('Get result {}'.format(result_value))
                snmp_result[key] = result_value
            except Exception as e:
                print(e)

        snmp_status = \
            ups_status.get(snmp_result.get('status')) if ups_status.get(snmp_result.get('status')) else 'unknown'
        snmp_power_left = int(snmp_result.get('power_left')) if snmp_result.get('power_left') else 61

        if snmp_result.get('status') != '2':
            s = u.name + ' UPS ' + u.ip + ' ' + snmp_status
            alarm_list.append(s)

        if snmp_result.get('status') != '2' and snmp_power_left < 80:
            s = u.name + ' UPS ' + u.ip + ' ' + 'UPS电力低于80%'
            alarm_list.append(s)

    if len(alarm_list) > 0:
        logger.info('UPS ALARM')
        AlarmPolicy.alarm(alarm_content=alarm_list, alarm_type='1')
    else:
        logger.info('There is no ups alarm')

    db.session.expire_all()
    db.session.close()


def pon_alarm_in_time_range(start_time, end_time):
    logger.debug('Start to alarm today\'s pon fail record')
    to_be_alarmed = PonAlarmRecord.query.filter(PonAlarmRecord.last_fail_time.between(start_time, end_time),
                                                PonAlarmRecord.status.__eq__(0),
                                                PonAlarmRecord.ontid.__eq__("PON")).all()

    if to_be_alarmed:
        alarm_list = []
        for olarm in to_be_alarmed:
            device_name = olarm.device_name if olarm.device_name else 'OLT'
            c = device_name + '( ' + olarm.ip + ' ) 的' + \
                str(olarm.frame) + '/' + str(olarm.slot) + '/' + str(olarm.port) + \
                ' 无收光, 疑似断线.\n'
            alarm_list.append(c)

            # 此处可根据该端口注册的信息，查询用户注册结果来判断涉及的社区
            ont_verbose = requestVerboseInfo.request_ontinfo(device_ip=olarm.ip,
                                                             fsp=[str(olarm.frame), str(olarm.slot), str(olarm.port)],
                                                             ontid_list='all')

            if ont_verbose.get('status') == 'OK':
                pass

            logger.warn('{} 此端口断线过 {} 次'.format(c, str(olarm.fail_times)))

        if len(alarm_list) > 0:
            AlarmPolicy.alarm(alarm_content=alarm_list, alarm_type='3')
        else:
            logger.info('There is no alarm')
    else:
        logger.info('There is no olt alarm now')


def lots_ont_losi_alarm(start_time, end_time):
    """
    定时器调用，用于检测是否有pon口下光猫批量下线的情况
    :param start_time: 检索开始时间
    :param end_time: 检索结束时间
    :return:
    """
    ont_down_in_same_time = PonAlarmRecord.query.filter(PonAlarmRecord.last_fail_time.between(start_time, end_time),
                                                        PonAlarmRecord.status.__eq__(0),
                                                        PonAlarmRecord.ontid.__ne__("PON")).all()
    dict_ont_down_in_same_time = defaultdict(list)
    alarm_list = []
    if ont_down_in_same_time:
        for ont in ont_down_in_same_time:
            dict_ont_down_in_same_time[(ont.device_name,
                                        ont.ip, ont.frame, ont.slot, ont.port,
                                        ont.last_fail_time)].append(ont.ontid)
        for sametimedown_info, sametimedown_ontid in dict_ont_down_in_same_time.items():
            if len(set(sametimedown_ontid)) > 1:
                c = sametimedown_info[0] + '( ' + sametimedown_info[1] + ' ) 的' + \
                    str(sametimedown_info[2]) + '/' + str(sametimedown_info[3]) + '/' + str(sametimedown_info[4]) + \
                    '于' + sametimedown_info[5].strftime('%Y-%m-%d %H:%M:%S') + ' 同时因光的原因下线.共' + \
                    str(len(set(sametimedown_ontid))) + ' 台ONT。ONT ID:\n' + str(set(sametimedown_ontid)) + '\n\n'

                hash_id = HashContent.md5_content(c)

                if not OntAccountInfo.query.filter_by(hash_id=hash_id).first():
                    # 向founderbn_nmp项目提交查询请求，获取对应的ont用户信息
                    # 如果此条告警的附加信息已经存在，则不再进行更新
                    # requestVerboseInfo.request_ontinfo 返回的是json
                    ont_verbose = requestVerboseInfo.request_ontinfo(device_ip=sametimedown_info[1],
                                                                     fsp=sametimedown_info[2:5],
                                                                     ontid_list=list(set(sametimedown_ontid)))
                    if ont_verbose.get('status') == 'OK':

                        # 将该条告警信息以MD5的方式作为唯一标签，把对应的ontid信息存储到OntAccountInfo表中
                        # 在AlarmPolicy.alarm中增加alarm_attach_detail方法对OntAccountInfo表的查询（通过MD5），
                        # 如果有，则发送微信的时候添加对应的用户信息

                        account_info_list = ont_verbose['content']  # list
                        attach = ''  # 附件告警信息
                        for account_info in account_info_list:
                            if len(account_info['customerListInfo']['customerList']) > 0:
                                customer_info = account_info['customerListInfo']['customerList'][0]
                                attach += '\n' + customer_info['accountId'] + ' ' + \
                                          customer_info['communityName'] + '/' + customer_info['aptNo']

                        add_verbose_info = OntAccountInfo(hash_id=hash_id, account_info=attach)
                        db.session.add(add_verbose_info)
                        db.session.commit()

                        db.session.expire_all()
                        db.session.close()

                # 添加到告警列表
                alarm_list.append(c)
                logger.debug(c)

    if len(alarm_list) > 0: # 如果存在告警，则调用alarm方法
        AlarmPolicy.alarm(alarm_content=alarm_list, alarm_type='4')
    else:
        logger.info('There is no alarm')


def per_ont_losi_alarm(start_time, end_time, alarm_times=100):
    """
    ont频繁上下线告警，目前仅做每天0点调用后发送邮件
    :param start_time:
    :param end_time:
    :param alarm_times: 累积下线次数
    :return:
    """
    ont_down_over_times = PonAlarmRecord.query.filter(PonAlarmRecord.last_fail_time.between(start_time, end_time),
                                                      PonAlarmRecord.fail_times.__ge__(alarm_times),
                                                      PonAlarmRecord.ontid.__ne__("PON")).all()
    alarm_list = []
    if ont_down_over_times:
        for ont in ont_down_over_times:
            c = ont.device_name + '(' + ont.ip + ') 的' + \
                str(ont.frame) + '/' + str(ont.slot) + '/' + str(ont.port) + ' ONT ID:' + str(ont.ontid) \
                + '因光的原因累积断线超过' + str(alarm_times) + '次, 请尽快排查\n\n'

            # 告警后fail_times计数器清零
            ont.fail_times = 0
            db.session.add(ont)
            db.session.commit()

            alarm_list.append(c)
            logger.debug(c)

    SM = SendMail.sendmail(subject='ONT LOSi 告警汇总', mail_to='597796137@qq.com')
    content = '\n'.join(alarm_list)
    msg = SM.addMsgText(content, 'plain', 'gb2312')
    SM.send(addmsgtext=msg)


def pon_state_check():
    """
    用于检测pon口最终状态,并根据最后下线用户的时间和下线原因,猜测pon口down的原因,如果猜测是光缆问题则告警
    :param:
    :return:
    """

    def __do_check(ip):
        """
        这个方法用来再次检查pon口状态, pon_state_check的调用,受计时器的控制,也就是在x时间之后再次检查pon口,如果还是down的状态
        则检查pon口下所有ont下线的原因,如果发现匹配时间上,ont下线的原因是LOSI,则认为是光的原因下线,状态是0, 如果是其它原因则状态为2
        :param ip:  需要检查的OLT的IP地址
        :return: 无返回
        """
        two_words = re.compile(r'([\w+\s+]*)\s+([\w+\-\s+:]*$)')
        reg_datetime = re.compile(r'(\d+-\d+-\d+\s+\d+:\d+:\d+)')
        reg_mac = re.compile(r'[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}')
        logger.info('Start to check {} OLT'.format(ip))
        value = {}
        # 增加了status 为-1的状态，用于标识怀疑是pon口掉线的端口，通过do_check来确认
        pon_info = PonAlarmRecord.query.filter_by(status=-1, ip=ip, ontid='PON').all()
        for pon_obj in pon_info:
            logger.debug('fsp: {} {} {}'.format(pon_obj.frame, pon_obj.slot, pon_obj.port))
            value[(pon_obj.frame, pon_obj.slot, pon_obj.port)] = pon_obj

        device_info = Device.query.filter_by(ip=ip).first()
        t = Telnet5680T.TelnetDevice(mac='', host=device_info.ip, username=device_info.login_name,
                                     password=device_info.login_password)

        for fsp, db_obj in value.items():
            t.go_into_interface_mode('/'.join(fsp))
            result = t.display_port_state(fsp[2])

            for line in result:
                if re.search(r'Port state', line):
                    logger.debug(line)
                    port_state = re.findall(two_words, line)[0][1]
                elif re.search(r'Last up time', line):
                    logger.debug(line)
                    last_up_time = re.findall(two_words, line)[0][1]
                elif re.search(r'Last down time', line):
                    logger.debug(line)
                    last_down_time = re.findall(two_words, line)[0][1]

            try:
                last_fail_time = re.findall(reg_datetime, last_down_time)[0]
            except Exception as e:
                last_fail_time = None

            try:
                last_recovery_time = re.findall(reg_datetime, last_up_time)[0]
            except Exception as e:
                last_recovery_time = None

            logger.debug('last fail time: {}'.format(last_fail_time))
            logger.debug('last recovery time: {}'.format(last_recovery_time))

            if port_state == 'Online':
                logger.debug('port online')
                db_obj.status = 1
            elif port_state == 'Offline':
                logger.debug('port offline')

                ont_id_list = []
                for ont in t.display_ont_info(fsp[2]):
                    if re.search(reg_mac, ont):
                        logger.debug(ont)
                        ont_id_list.append(
                            re.findall(r'(\d+)\s+[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}', ont)[0])
                ont_count = len(set(ont_id_list))
                confirm_flag = False
                if ont_count > 0:
                    pon_flag = 0
                    for oid in ont_id_list:
                        register_info = t.check_register_info(p=str(fsp[2]), id=oid)
                        logger.debug(register_info)
                        for line in register_info:
                            if re.search(r'DownTime', str(line)):
                                downtime_find = re.findall(reg_datetime, line)
                                if downtime_find:
                                    downtime = downtime_find[0]
                                    logger.debug(str(line))
                                    ldt = datetime.datetime.strptime(downtime, "%Y-%m-%d %H:%M:%S")
                                    logger.debug(ldt)

                                    td = datetime.datetime.strptime(last_fail_time, "%Y-%m-%d %H:%M:%S") - ldt

                                    if td <= datetime.timedelta(seconds=0):
                                        pon_flag += 1
                                        logger.debug(td)

                                    else:
                                        logger.debug('break')
                                        break

                            elif re.search(r'DownCause', line):
                                logger.debug(line)
                                # 目前不考虑下线原因是掉电的断线原因

                                if re.search(r'LOS[i|I]', line):
                                    if pon_flag > 0:
                                        pon_flag += 1
                                    logger.debug('LOSi match: {}'.format(line))
                                else:
                                    logger.debug('Other cause match: {}'.format(line))
                                    pon_flag -= 1

                            if pon_flag >= 2:
                                logger.debug('confirm flag = True. pon_flag: {}'.format(pon_flag))
                                confirm_flag = True
                                break

                        if confirm_flag:
                            break

                logger.debug('final confirm flag is {}'.format(confirm_flag))
                db_obj.status = 0 if confirm_flag else 2

            db_obj.last_fail_time = last_fail_time
            db_obj.last_recovery_time = last_recovery_time

            db.session.add(db_obj)

        db.session.commit()
        db.session.expire_all()
        db.session.close()

    # start from here
    pon_check = [pon.ip for pon in PonAlarmRecord.query.filter_by(status=-1, ontid='PON').all()]

    r = []
    for ip in set(pon_check):
        logger.info('checking {}'.format(ip))
        i = threading.Thread(target=__do_check, args=(ip,))
        r.append(i)
        i.start()

    for t in r:
        logger.debug('######### {}'.format(t))
        t.join()

    db.session.expire_all()
    db.session.close()
    return True


def olt_check():
    """
    定时器调用
    :return:
    """
    pon_state_check()

    today = datetime.datetime.today()
    start_time = datetime.datetime(today.year, today.month, today.day, 0, 0, 0)
    end_time = datetime.datetime(today.year, today.month, today.day, 23, 59, 59)

    pon_alarm_in_time_range(start_time=start_time, end_time=end_time)

    lots_ont_losi_alarm(start_time=start_time, end_time=end_time)

    db.session.expire_all()
    db.session.close()


def per_ont_check():
    """
    定时器调用
    :return:
    """
    today = datetime.datetime.today()
    start_time = datetime.datetime(today.year, today.month, today.day, 0, 0, 0)
    end_time = datetime.datetime(today.year, today.month, today.day, 23, 59, 59)

    per_ont_losi_alarm(start_time=start_time, end_time=end_time)

    db.session.expire_all()
    db.session.close()


def unalarmed_polling():
    """
    定时器调用
    :return:
    """
    AlarmPolicy.alarmMonitor()
    db.session.expire_all()
    db.session.close()


def py_syslog_olt_monitor(host, logmsg):
    """
    处理py_syslog调用，用于处理olt发来的日志
    :param host:
    :param logmsg:
    :return:
    """
    logger.debug("olt syslog monitor {} {}".format(host, logmsg))
    device = Device.query.filter_by(ip=host).first()
    device_name = device.device_name if device else 'None'
    ont_down = re.compile(r'(FAULT).*?\n*.*?(fiber is broken).*?\n*.*?(EPON ONT)|'
                          r'The feed fiber is broken or OLT can not receive any expected')
    ont_up = re.compile(r'(RECOVERY CLEARED).*?\n*.*?(OLT can receive expected optical signals)|'
                        r'OLT can receive expected optical signals from ONT')
    ontid = ''
    try:
        fail = re.search(ont_down, logmsg)
        recovery = re.search(ont_up, logmsg)
        alert_time = datetime.datetime.strptime(
            re.findall(r'(\d+-\d+-\d+\s+\d+:\d+:\d+)', logmsg)[0],
            '%Y-%m-%d %H:%M:%S'
        )
        try:
            f, s, p, ontid = \
                re.findall(r'FrameID:\s+(\d+),\s+SlotID:\s+(\d+),\s+PortID:\s+(\d+),\s+ONT\s+ID:\s+(\d+)', logmsg)[0]
            pon_history = PonAlarmRecord.query.filter_by(ip=host, frame=f, slot=s, port=p, ontid=ontid).first()
        except Exception as e:
            try:
                f, s, p = \
                re.findall(r'FrameID:\s+(\d+),\s+SlotID:\s+(\d+),\s+PortID:\s+(\d+)', logmsg)[0]
                pon_history = PonAlarmRecord.query.filter_by(ip=host, frame=f, slot=s, port=p, ontid='PON').first()
            except Exception as e:
                logger.warning(e)
                return False

        ontid = ontid if ontid else "PON"

        if pon_history:
            if fail:
                pon_history.last_fail_time = alert_time
                # 如果是PON口fail, 那么在计划任务中会再次检测PON口状态, 因此当写入新的syslog服务时,如果是fail 则status 为-1,
                # 表示此事失效,但是不确定
                pon_history.status = -1 if ontid == 'PON' else 0
                pon_history.fail_times += 1
            if recovery:
                pon_history.last_recovery_time = alert_time
                pon_history.status = 1
            db.session.add(pon_history)
        else:
            if fail:
                pon_new = PonAlarmRecord(device_name=device_name, ip=host,
                                         frame=f, slot=s, port=p, ontid=ontid, fail_times=1, status=0,
                                         last_fail_time=alert_time, create_time=time.localtime())
                db.session.add(pon_new)

            if recovery:
                pon_new = PonAlarmRecord(device_name=device_name, ip=host,
                                         frame=f, slot=s, port=p, ontid=ontid, fail_times=0, status=1,
                                         last_recovery_time=alert_time, create_time=time.localtime())

                db.session.add(pon_new)
        db.session.commit()
    except Exception as e:
        logger.warning("Host {} log msg {} not match".format(host, logmsg))


def general_syslog_monitor(host, logmsg):
    """
    处理py_syslog发来的日志，处理除OLT外的日志
    :param host:
    :param logmsg:
    :return:
    """
    logger.debug("{} {}".format(host, logmsg))
    device = Device.query.filter_by(ip=host).first()
    device_name = device.device_name if device else 'None'
    n = logmsg.find('>')
    c = device_name + ' ' + host + \
        ' 产生syslog告警 ' + logmsg[26:] + '\n'

    AlarmPolicy.alarm(alarm_content=[c], alarm_type='2')
