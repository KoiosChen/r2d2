from flask import request, jsonify
from . import main
from ..models import T2MRegister
from collections import defaultdict
import base64


def nesteddict():
    """
    构造一个嵌套的字典
    :return:
    """
    return defaultdict(nesteddict)


@main.route('/t2m_register', methods=["POST"])
def t2m_register():
    try:
        registerInfo = base64.b64decode(request.json['sysid'].strip()).decode().strip()
        print(registerInfo)
        if not registerInfo:
            return jsonify({'status': 'false', 'content': '未提交正确的信息'})
        else:
            register_record = T2MRegister.query.filter_by(sysid=registerInfo.strip()).first()
            print(register_record)
            if not register_record:
                return jsonify({'status': 'false', 'content': '此设备未绑定'})
            else:
                return jsonify(
                    {'status': 'true',
                     'content': "register successful",
                     'configurl': register_record.configurl,
                     'ssurl': register_record.ssurl,
                     'username': register_record.username,
                     'method': register_record.encryption_method,
                     'password': register_record.password,
                     'dns': register_record.dns})
    except Exception as e:
        return jsonify({'status': 'false', 'content': str(e)})
