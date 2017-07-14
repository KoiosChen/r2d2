#!/usr/bin/env python
import os
import multiprocessing
from app import create_app, db, scheduler, logger
from app.models import User, Role, MachineRoom, Device, AlarmRecord, DutyAttendedTime, DutySchedule, CONFIG_FILE_PATH
from flask_script import Manager, Shell
from flask_migrate import Migrate, MigrateCommand
from app.R2D2 import ups_monitor, unalarmed_polling, cacti_db_monitor,\
    pon_state_check, pon_alarm_in_time_range, lots_ont_losi_alarm
from app.MyModule import AlarmPolicy, PhoneNumber, AddDutyMember, OperateDutyArrange, WechatAlarm, GetCactiPic, \
    py_syslog
from app.MyModule import SendMail, SeqPickle, SchedulerControl

__author__ = 'Koios'

app = create_app(os.getenv('FLASK_CONFIG') or 'default')
manager = Manager(app)
migrate = Migrate(app, db)

# 启动syslog服务
syslog_process = multiprocessing.Process(target=py_syslog.py_syslog)
syslog_process.daemon = True
syslog_process.start()


# 检查许可, 如果传入的参数为'1', 则用户若删除licence.pkl文件, 每次重启服务都会产生一个新的licence.pkl文件, 并可以使用7天
init_status = '1'
SeqPickle.checkLicence(init_status)
if init_status == '0':
    # 如果init_status 是0, 表示默认不支持用户使用, 停止所有计划任务
    SchedulerControl.scheduler_pause()
else:
    # 根据数据库配置修改scheduler计划, 用户覆盖默认配置文件中的配置
    SchedulerControl.scheduler_modify()


def make_shell_context():
    return dict(app=app, db=db, User=User, Role=Role, MachineRoom=MachineRoom, Device=Device,
                cacti=cacti_db_monitor, ups=ups_monitor,
                polling=unalarmed_polling, pon=pon_state_check, today=pon_alarm_in_time_range,
                alarm=AlarmPolicy, AlarmRecord=AlarmRecord,
                DutyAttendedTime=DutyAttendedTime, DutySchedule=DutySchedule, PhoneNumber=PhoneNumber,
                AddDutyMember=AddDutyMember, OperateDutyArrange=OperateDutyArrange, WechatAlarm=WechatAlarm,
                GetCactiPic=GetCactiPic, ont_alarm_in_time_range=lots_ont_losi_alarm, sendmail=SendMail)


manager.add_command("shell", Shell(make_context=make_shell_context))
manager.add_command('db', MigrateCommand)


if __name__ == '__main__':
    manager.run()
