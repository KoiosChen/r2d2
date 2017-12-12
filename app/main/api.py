from flask import request, jsonify
from . import main
from ..models import AlarmRecord, PonAlarmRecord, Permission
from .. import redis_db, logger, db
import json
from ..decorators import permission_required
import re
from flask_login import current_user


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

        if alarm_record.alarm_type == 4:
            print(alarm_record.content)
            ontid = [int(i) for i in eval(re.findall(r'(\{*.+\})', alarm_record.content)[0])]
            ip = re.findall(r'(\d+\.\d+\.\d+\.\d+)', alarm_record.content)[0]
            f, s, p = re.findall(r'(\d+/\d+/\d+)', alarm_record.content)[0].split('/')
            print(f,s,p,ontid,ip)
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