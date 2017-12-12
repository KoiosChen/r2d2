import socket
import sys
import queue
import threading
import re
from ..r2d2.SyslogWorker import py_syslog_olt_monitor, general_syslog_monitor
from ..models import SyslogAlarmConfig, Syslog, syslog_facility, syslog_serverty
from .. import db, logger
import datetime


def write_syslog_to_db(host, logmsg):
    logger.debug('writing syslog to db')
    n = logmsg.find('>')
    serverty = int(logmsg[1:n]) & 0x0007
    facility = (int(logmsg[1:n]) & 0x03f8) >> 3
    if serverty <= 3:  # 只记录error - emergency 的syslog
        try:
            alert_time = datetime.datetime.strptime(
                re.findall(r'(\d+-\d+-\d+\s+\d+:\d+:\d+)', logmsg)[0],
                '%Y-%m-%d %H:%M:%S'
            )
        except Exception as e:
            alert_time = datetime.datetime.now()
        write_log = Syslog(device_ip=host,
                           logmsg=logmsg[26:],
                           logtime=alert_time,
                           facility=syslog_facility[facility],
                           serverty=syslog_serverty[serverty])
        db.session.add(write_log)
        db.session.commit()
        db.session.expire_all()
        db.session.close()


def syslog_allocating(host, logmsg):

    syslog_alarm_config = [(c.alarm_keyword, c.alarm_type) for c in
                           SyslogAlarmConfig.query.filter_by(alarm_status=1).order_by(
                               SyslogAlarmConfig.alarm_level).all()]
    match_flag = False
    for key, alarm_type in syslog_alarm_config:
        regex_ = re.compile(key)
        if re.search(regex_, logmsg):
            match_flag = True
            if alarm_type == 'olt':
                logger.debug('allocating syslog task to olt syslog process')
                py_syslog_olt_monitor(host, logmsg)
                break
            elif alarm_type == 'filter':
                logger.debug('Syslog filtered {} {}.'.format(host, logmsg))
                break
            else:
                logger.debug('allocating syslog task to normal syslog precess')
                write_syslog_to_db(host, logmsg)
                general_syslog_monitor(host, logmsg)
                break
    # 若没有在syslog_alarm_config中匹配到的syslog,都调用write_syslog_to_db
    if not match_flag:
        write_syslog_to_db(host, logmsg)


class StartThread(threading.Thread):
    def __init__(self, q):
        threading.Thread.__init__(self)
        self.queue = q

    def run(self):
        while True:
            syslog_msg, addr = self.queue.get()
            syslog_msg = syslog_msg.decode()
            host = addr[0]
            try:
                logger.debug("{} {} {} {}".format(host, type(host), syslog_msg, type(syslog_msg)))
                logger.debug("ip:{} msg:{}".format(host, syslog_msg))
                syslog_allocating(host, syslog_msg)
            except Exception as e:
                logger.error(e)
                sys.exit(1)

            db.session.expire_all()
            db.session.close()
            self.queue.task_done()


def py_syslog():
    bufsize = 8192
    port = 514
    thread_num = 20

    q = queue.Queue(maxsize=1000)

    for threads_pool in range(thread_num):
        t = StartThread(q)
        t.setDaemon(True)
        t.start()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", port))
    except Exception as e:
        logger.error('SYSLOG ERROR: {}'.format(e))
        sys.exit(1)

    logger.info("----------------syslog server is started----------------\n")

    try:
        while 1:
            try:
                q.put(sock.recvfrom(bufsize))

            except Exception as e:
                logger.warning(e)
                sys.exit(1)
        # q.join()

    except Exception as e:
        logger.warning(e)
        sys.exit(1)

if __name__ == '__main__':
    py_syslog()
