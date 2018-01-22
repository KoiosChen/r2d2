from flask import request, jsonify
from . import main
from ..models import AlarmRecord, PonAlarmRecord, Permission, PiRegister, User, PcapOrder, PcapResult
from .. import redis_db, logger, db
import json
from ..decorators import permission_required
import re
from flask_login import current_user
import time
import requests
from collections import defaultdict
import os


def nesteddict():
    """
    构造一个嵌套的字典
    :return:
    """
    return defaultdict(nesteddict)


@main.route('/submit_pcap_order', methods=["POST"])
def submit_pcap_order():
    data = request.get_json()
    submit_order = PcapOrder(id=data['id'],
                             account_id=data['accountId'],
                             login_name=data['login_name'],
                             username=data['username'],
                             question_description=data['question'],
                             create_time=time.localtime())
    db.session.add(submit_order)
    db.session.commit()
    return jsonify({'status': 'ok', 'content': '工单已提交，请携带对应设备上门'})


@main.route('/upload_files', methods=["POST"])
def upload_files():
    files = request.files['upload_file']
    print('got file name: ', files.filename)
    files.save(os.path.join('/Users/Peter/Desktop', files.filename))
    return jsonify({'status': 'ok', 'content': 'got files'})


@main.route('/pi_register', methods=["POST"])
def pi_register():
    registerInfo = request.json['sysid'].strip()
    print(registerInfo)
    if not registerInfo:
        return jsonify({'status': 'fail', 'content': '未提交正确的信息'})
    else:
        register_record = PiRegister.query.filter_by(sysid=registerInfo.strip()).first()
        print(register_record)
        if not register_record:
            return jsonify({'status': 'fail', 'content': '此设备未绑定'})
        else:
            userinfo = User.query.filter_by(email=register_record.username, status=1).first()
            if not userinfo:
                return jsonify({'status': 'fail', 'content': '绑定用户不存在或者已经失效'})
            else:
                print(userinfo)
                account_dict = nesteddict()
                processing_orders = PcapOrder.query.filter_by(status=1, login_name=register_record.username).all()
                headers = {'Content-Type': 'application/json', "encoding": "utf-8"}
                send_sms_url = 'http://127.0.0.1:54322/get_customer_info'

                for o in processing_orders:
                    send_content = {"account_id": o.account_id, "loginName": "admin", "_hidden_param": True}
                    r = requests.post(send_sms_url, data=json.dumps(send_content, ensure_ascii=False).encode('utf-8'),
                                      headers=headers)
                    result = r.json()
                    if result['status'] == 'OK':
                        account_dict[o.account_id] = \
                            {"password": result['content']['customerListInfo']['customerList'][0]['password'],
                             "question": o.question_description,
                             "order_id": o.id}
                        print(result)

                register_record.times += 1
                register_record.last_register_time = time.localtime()
                db.session.add(register_record)
                db.session.commit()
                return jsonify(
                    {'status': 'ok', 'content': account_dict, 'url': {'r2d2_url': 'http://192.168.2.112:54321',
                                                                      'onu_url': 'http://192.168.2.112:54322',
                                                                      'iperf_server': '192.168.2.112'}})


@main.route('/delete_alarm_record', methods=['POST'])
def delete_alarm_record():
    """
    用于删除告警记录。alarm_record表不删除，只是将alarm_type修改为999；如果是alarm_type 为4， 那么要删除pon_alarm_record中的记录
    POST的是
    :return:
    """
    try:
        if not current_user.can(Permission.NETWORK_MANAGER):
            logger.warn('This user\'s action is not permitted!')
            return jsonify({'status': 'Fail', 'content': '此账号没有权限删除告警记录'})
        print('delete')
        alarm_id = request.json
        print(alarm_id)

        id = alarm_id['alarm_id']

        print(id)

        print('start check')

        alarm_record = AlarmRecord.query.filter_by(id=id).first()

        print(alarm_record)
        print(alarm_record.alarm_type)

        if alarm_record.alarm_type == 4 or alarm_record.alarm_type == 3:
            print(alarm_record.content)
            try:
                ontid = [int(i) for i in eval(re.findall(r'(\{*.+\})', alarm_record.content)[0])]
            except Exception as e:
                ontid = ['PON']
            ip = re.findall(r'(\d+\.\d+\.\d+\.\d+)', alarm_record.content)[0]
            f, s, p = re.findall(r'(\d+/\d+/\d+)', alarm_record.content)[0].split('/')
            print(f, s, p, ontid, ip)
            for ont in ontid:
                pon_alarm_record = PonAlarmRecord.query.filter_by(ip=ip, frame=f, slot=s, port=p, ontid=ont).first()
                if not pon_alarm_record:
                    continue
                db.session.delete(pon_alarm_record)
                db.session.commit()

        alarm_record.alarm_type = 999
        db.session.add(alarm_record)
        db.session.commit()

        return jsonify({'status': 'OK', 'content': '记录已删除'})

    except Exception as e:
        print(e)
        return jsonify({'status': 'Fail', 'content': str(e)})
