from flask import redirect, session, url_for, render_template, flash, request, jsonify, send_from_directory
from flask_login import login_required
from ..models import *
from ..decorators import permission_required
from .. import db, logger, scheduler
from .forms import PostForm, DeviceForm, RegistrationForm, AreaConfigForm, UserModal, AreaModal
from . import main
import time
from ..MyModule import OperateDutyArrange
from ..MyModule.GetConfig import get_config
from ..MyModule.UploadFile import uploadfile
from ..MyModule.SeqPickle import get_pubkey, update_crypted_licence
from werkzeug.utils import secure_filename
import json
from bs4 import BeautifulSoup
import datetime
import os
import re
import requests
from sqlalchemy import or_, and_


def get_device_info(machine_room_id):
    """
    :param machine_room_id:
    :return:
    """
    device_info = Device.query.filter_by(machine_room_id=machine_room_id).all()
    logger.debug('device list: {} '.format(device_info))
    return device_info if device_info else False


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def gen_file_name(filename):
    """
    If file was exist already, rename it and return a new name
    """

    i = 1
    while os.path.exists(os.path.join(UPLOAD_FOLDER, filename)):
        name, extension = os.path.splitext(filename)
        filename = '%s_%s%s' % (name, str(i), extension)
        i += 1

    return filename


IGNORED_FILES = set(['.gitignore'])


@main.route('/', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.MAN_ON_DUTY)
def index():
    if request.method == 'GET':
        operator = [(str(user_info.id), user_info.username) for user_info in User.query.all()]
        modal_form = PostForm()
        logger.info('User {} is checking alarm record'.format(session['LOGINNAME']))
        return render_template('alarm_record.html',
                               operator=operator,
                               modal_form=modal_form)
    elif request.method == 'POST':
        print(request.form.get('latest_editor'), request.form.get('search_content'), request.form.get('search_date'))
        latest_editor = request.form.get('latest_editor', '%')
        search_content = '%' + request.form.get('search_content', '%') + '%'
        search_date = request.form.get('search_date')
        if search_date:
            start_time, stop_time = search_date.split(' - ')
        start_time = datetime.datetime.strptime(start_time + ' 00:00:00',
                                                '%Y-%m-%d %H:%M:%S') if search_date else datetime.datetime(2000, 1, 1,
                                                                                                           0, 0, 0)
        stop_time = datetime.datetime.strptime(stop_time + ' 23:59:59',
                                               '%Y-%m-%d %H:%M:%S') if search_date else datetime.datetime(2100, 12, 31,
                                                                                                          23, 59, 59)

        print(start_time, stop_time)

        draw = request.form.get('draw')
        page_start = int(request.form.get('start', '0'))
        page_end = page_start + int(request.form.get('length'))

        posted_body = Post.query.order_by(Post.timestamp.desc()).all()
        all_user_dict = {user.id: {'username': user.username, 'phoneNum': user.phoneNum}
                         for user in User.query.filter_by(status=1).all()}
        pl = []
        post_info = {}
        for p in posted_body:
            if p.alarm_id not in pl:
                pl.append(p.alarm_id)
                post_info[p.alarm_id] = {'author_id': p.author_id, 'timestamp': p.timestamp}

        call_record = {r.callId: r.phoneNum
                       for r in CallRecordDetail.query.filter(CallRecordDetail.respCode.__eq__(000000)).all()}

        if request.form.get('latest_editor') or request.form.get('search_content') or request.form.get('search_date'):
            if request.form.get('latest_editor') and Post.query.filter_by(author_id=latest_editor).all():
                data = [[ui.id,
                         ui.content,
                         all_user_dict[post_info[ui.id]['author_id']]['username'] if ui.id in post_info and
                                                                                     post_info[ui.id][
                                                                                         'author_id'] in all_user_dict else '',
                         post_info[ui.id]['timestamp'] if ui.id in post_info else '',
                         call_record[ui.lastCallId] if ui.lastCallId in call_record else '',
                         ui.create_time,
                         """<a data-toggle="modal" data-target="#attachment" onclick="attachmentInfo(""" + str(ui.id) + """)">
                                                             <img src="../static/attachment.png" alt="" title=""
                                                             border="0" /></a>""",
                         """<a data-toggle="modal" data-target="#update" onclick="editInfo(""" + str(ui.id) + """)">
                                             <img src="../static/edit.png" alt="" title=""
                                             border="0" /></a>""",
                         """<a  onClick="return HTMerDel(""" + str(ui.id) + """)">
                                                  <img src="../static/trash.png" alt="" title="" border="0" /></a>"""]
                        for ui in AlarmRecord.query.filter(AlarmRecord.content.like(search_content),
                                                           AlarmRecord.alarm_type.__ne__(999),
                                                           AlarmRecord.create_time.between(start_time,
                                                                                           stop_time)).order_by(
                        AlarmRecord.create_time.desc()).all()
                        if ui.id in post_info and post_info[ui.id]['author_id'] == int(latest_editor)]

            elif request.form.get('latest_editor') and not Post.query.filter_by(author_id=latest_editor).all():
                # 防止异常
                data = []

            else:
                data = [[ui.id,
                         ui.content,
                         all_user_dict[post_info[ui.id]['author_id']]['username'] if ui.id in post_info and
                                                                                     post_info[ui.id][
                                                                                         'author_id'] in all_user_dict else '',
                         post_info[ui.id]['timestamp'] if ui.id in post_info else '',
                         call_record[ui.lastCallId] if ui.lastCallId in call_record else '',
                         ui.create_time,
                         """<a data-toggle="modal" data-target="#attachment" onclick="attachmentInfo(""" + str(ui.id) + """)">
                                                                             <img src="../static/attachment.png" alt="" title=""
                                                                             border="0" /></a>""",
                         """<a data-toggle="modal" data-target="#update" onclick="editInfo(""" + str(ui.id) + """)">
                                                             <img src="../static/edit.png" alt="" title=""
                                                             border="0" /></a>""",
                         """<a  onClick="return HTMerDel(""" + str(ui.id) + """)">
                                                  <img src="../static/trash.png" alt="" title="" border="0" /></a>"""]
                        for ui in AlarmRecord.query.filter(AlarmRecord.content.like(search_content),
                                                           AlarmRecord.alarm_type.__ne__(999),
                                                           AlarmRecord.create_time.between(start_time,
                                                                                           stop_time)).order_by(
                        AlarmRecord.create_time.desc()).all()]

            recordsTotal = len(data)
        else:
            data = [[ui.id,
                     ui.content,
                     all_user_dict[post_info[ui.id]['author_id']]['username'] if ui.id in post_info.keys() and
                                                                                 post_info[ui.id][
                                                                                     'author_id'] in all_user_dict.keys() else '',
                     post_info[ui.id]['timestamp'] if ui.id in post_info else '',
                     call_record[ui.lastCallId] if ui.lastCallId in call_record else '',
                     ui.create_time,
                     """<a data-toggle="modal" data-target="#attachment" onclick="attachmentInfo(""" + str(ui.id) + """)">
                                                                         <img src="../static/attachment.png" alt="" title=""
                                                                         border="0" /></a>""",
                     """<a data-toggle="modal" data-target="#update" onclick="editInfo(""" + str(ui.id) + """)">
                             <img src="../static/edit.png" alt="" title=""
                             border="0" /></a>""",
                     """<a  onClick="return HTMerDel(""" + str(ui.id) + """)">
                                                  <img src="../static/trash.png" alt="" title="" border="0" /></a>"""]
                    for ui in AlarmRecord.query.filter(AlarmRecord.alarm_type.__ne__(999)).order_by(
                    AlarmRecord.create_time.desc()).all()]
            recordsTotal = AlarmRecord.query.count()

        rest = {'draw': int(draw),
                'recordsTotal': recordsTotal,
                'recordsFiltered': recordsTotal,
                'data': data[page_start:page_end]
                }
        return jsonify(rest)


@main.route('/post_body', methods=['POST'])
@login_required
@permission_required(Permission.MAN_ON_DUTY)
def post_body():
    alarm_id = request.form.get('alarm_id')
    body = request.form.get('body')
    print('view', body)

    post = Post(body=body, author_id=str(session['SELFID']), alarm_id=alarm_id)
    db.session.add(post)
    db.session.commit()
    return json.dumps({"status": 'OK'}, ensure_ascii=False)


@main.route('/get_alarm_detail_info', methods=['POST'])
@login_required
@permission_required(Permission.MAN_ON_DUTY)
def get_alarm_detail_info():
    params = request.get_data()
    jl = params.decode('utf-8')
    j = json.loads(jl)
    alarm_record = AlarmRecord.query.get(j.get('alarm_id'))

    call_record = {r.callId: r.phoneNum
                   for r in CallRecordDetail.query.filter(CallRecordDetail.respCode.__eq__(000000)).all()}

    alarm_detail_info = {
        'phoneNum': call_record[alarm_record.lastCallId] if alarm_record.lastCallId in call_record.keys() else None,
        'call_status': alarm_record_state[alarm_record.state],
        'times': alarm_record.calledTimes}

    return jsonify(json.dumps(alarm_detail_info, ensure_ascii=False))


@main.route('/get_attachment', methods=['POST'])
@login_required
@permission_required(Permission.MAN_ON_DUTY)
def get_attachment():
    params = request.get_data()
    jl = params.decode('utf-8')
    j = json.loads(jl)
    print(j)
    alarm_record = AlarmRecord.query.get(j.get('id'))
    print(alarm_record.content_md5)

    attachment = OntAccountInfo.query.filter_by(hash_id=alarm_record.content_md5).first()

    if attachment:
        return jsonify({'status': 'OK', 'data': attachment.account_info})
    else:
        return jsonify({'status': 'Fail', 'data': 'Null'})


@main.route('/get_posted_body', methods=['POST'])
@login_required
@permission_required(Permission.MAN_ON_DUTY)
def get_posted_body():
    params = request.get_data()
    jl = params.decode('utf-8')
    j = json.loads(jl)
    posted_body = {}
    posts = Post.query.filter_by(alarm_id=j.get('alarm_id')).order_by(Post.timestamp.desc()).all()
    all_user = User.query.filter_by(status=1).all()
    all_user_dict = {}
    for user in all_user:
        all_user_dict[user.id] = {'username': user.username, 'phoneNum': user.phoneNum}
    i = 0
    for p in posts:
        posted_body[i] = {'username': all_user_dict[p.author_id]['username'],
                          'phoneNum': all_user_dict[p.author_id]['phoneNum'],
                          'body': p.body,
                          'body_html': p.body_html,
                          'timestamp': datetime.datetime.strftime(p.timestamp, '%Y-%m-%d %H:%M:%S')}
        i += 1
    print(posted_body)
    return jsonify(json.dumps(posted_body, ensure_ascii=False))


@main.route('/print_duty_schedule', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.MAN_ON_DUTY)
def print_duty_schedule():
    logger.info('User {} is checking duty schedule'.format(session['LOGINNAME']))

    return render_template('print_duty_schedule.html',
                           duty_schedule_status=duty_schedule_status)


@main.route('/print_duty_schedule_api', methods=['POST'])
@login_required
@permission_required(Permission.MAN_ON_DUTY)
def print_duty_schedule_api():
    logger.debug('selected_month')
    params = request.get_data()
    jl = params.decode('utf-8')
    j = json.loads(jl)
    print(int(j.get('selected_month')))
    title, duty_arrangement = OperateDutyArrange.print_duty_schedule(check_year=2017,
                                                                     check_month=int(j.get('selected_month')))

    posted_body = {'title': title,
                   'duty_arrangement': duty_arrangement,
                   }

    return jsonify(json.dumps(posted_body, ensure_ascii=False))


@main.route('/upload', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.ADMINISTER)
def upload():
    logger.info('User {} is uploading duty schedule'.format(session['LOGINNAME']))

    if request.method == 'POST':
        files = request.files['file']

        if files:
            filename = secure_filename(files.filename)
            filename = gen_file_name(filename)
            mime_type = files.content_type

            if not allowed_file(files.filename):
                result = uploadfile(name=filename, type=mime_type, size=0, not_allowed_msg="File type not allowed")

            else:
                # save file to disk
                uploaded_file_path = os.path.join(UPLOAD_FOLDER, filename)
                files.save(uploaded_file_path)

                # create thumbnail after saving
                if mime_type.startswith('image'):
                    pass

                # get file size after saving
                size = os.path.getsize(uploaded_file_path)

                # return json for js call back
                result = uploadfile(name=filename, type=mime_type, size=size)

            return json.dumps({"files": [result.get_file()]}, ensure_ascii=False)

    if request.method == 'GET':
        # get all file in ./data directory
        files = [f for f in os.listdir(UPLOAD_FOLDER) if
                 os.path.isfile(os.path.join(UPLOAD_FOLDER, f)) and f not in IGNORED_FILES]

        file_display = []

        for f in files:
            size = os.path.getsize(os.path.join(UPLOAD_FOLDER, f))
            file_saved = uploadfile(name=f, size=size)
            file_display.append(file_saved.get_file())

        return json.dumps({"files": file_display}, ensure_ascii=False)

    return redirect(url_for('upload_duty_schedule'))


@main.route("/show_image/<string:filename>", methods=['GET'])
def show_image(filename):
    return render_template('show_image.html',
                           filename=filename)


@main.route("/data/<string:filename>", methods=['GET'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def get_file(filename):
    return send_from_directory(os.path.join(UPLOAD_FOLDER), filename=filename)


@main.route('/upload_duty_schedule', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.ADMINISTER)
def upload_duty_schedule():
    return render_template('upload_duty_schedule.html')


@main.route("/delete/<string:filename>", methods=['DELETE'])
@login_required
@permission_required(Permission.ADMINISTER)
def delete(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)

    if os.path.exists(file_path):
        try:
            os.remove(file_path)

            return json.dumps({filename: 'True'})
        except:
            return json.dumps({filename: 'False'})


@main.route("/import_duty/<string:filename>", methods=['GET'])
@login_required
@permission_required(Permission.ADMINISTER)
def import_duty(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    logger.debug('file_path is {}'.format(file_path))

    if os.path.exists(file_path):
        try:
            logger.debug('do job')
            title, row_list = OperateDutyArrange.read_duty_arrange(file_path, 'Sheet1', True)
            import_result = OperateDutyArrange.add_duty_arrange(title, row_list)
            return jsonify(json.dumps({'status': import_result}, ensure_ascii=False))
        except:
            return jsonify(json.dumps({'status': '系统繁忙'}, ensure_ascii=False))


@main.route('/all_user', methods=['POST'])
@login_required
@permission_required(Permission.MAN_ON_DUTY)
def all_user():
    logger.info('User {} is getting all user dictionary'.format(session['LOGINNAME']))
    all_user = User.query.filter(User.status.__eq__(1), User.phoneNum.__ne__(None)).all()
    all_user_dict = {}
    for user in all_user:
        all_user_dict[user.id] = {'username': user.username, 'phoneNum': user.phoneNum}

    return jsonify(json.dumps(all_user_dict))


@main.route('/check_appointed_time_duty_engineer', methods=['POST'])
@login_required
@permission_required(Permission.MAN_ON_DUTY)
def check_appointed_time_duty_engineer():
    params = request.get_data()
    jl = params.decode('utf-8')
    j = json.loads(jl)
    print(j)

    logger.info('User {} is checking appointed time duty engineer'.format(session['LOGINNAME']))
    start_time, stop_time = re.findall(r'(\d+:\d+)--(\d+:\d+)', j.get('selected_duty_time'))[0]
    duty_attended_time_id = DutyAttendedTime.query.filter_by(start_time=start_time, stop_time=stop_time).first()
    duty_engineer = DutySchedule.query.filter_by(
        date_time=datetime.datetime.strptime(j.get('selected_date'), '%Y-%m-%d'),
        attended_time_id=duty_attended_time_id.id).all()

    r_json = {}
    for e in duty_engineer:
        username = User.query.get(e.userid)
        r_json[e.userid] = {'username': username.username,
                            'phoneNum': username.phoneNum,
                            'duty_status': duty_schedule_status[e.duty_status]}

    r = json.dumps(r_json, ensure_ascii=False)

    return jsonify(r)


@main.route('/operate_duty_arrange', methods=['POST'])
@login_required
@permission_required(Permission.ADMINISTER)
def operate_duty_arrange():
    params = request.get_data()
    jl = params.decode('utf-8')
    j = json.loads(jl)
    logger.debug(j)

    logger.info('User {} is operate duty arrange'.format(session['LOGINNAME']))

    result = OperateDutyArrange.change_duty_schedule_status(**j)

    r_json = {'status': result}

    r = json.dumps(r_json, ensure_ascii=False)

    return jsonify(r)


@main.route('/call_callback', methods=['POST'])
def callback():
    logger.debug('callback')
    resp = request.get_data()
    logger.debug(resp)
    soup = BeautifulSoup(resp, 'lxml')
    logger.info('call to {} status {}'.format(soup.called.string, soup.state.string))
    callback = VoiceNotifyCallBack(phoneNum=str(soup.called.string),
                                   state=str(soup.state.string),
                                   callId=str(soup.callid.string),
                                   create_time=time.localtime())

    db.session.add(callback)
    db.session.commit()

    call_record = CallRecordDetail.query.filter_by(callId=str(soup.callid.string)).first()

    alarm_record = AlarmRecord.query.filter_by(call_group=call_record.call_group).all()

    for r in alarm_record:

        # update state in the alarm record
        if soup.state.string == '0':
            r.state = 9
        else:
            r.state = 3

        db.session.add(r)
    db.session.commit()

    return '', 200


@main.route('/user_delete', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.FOLLOW)
def user_delete():
    user_id = request.args.get('user_id')
    user_tobe_deleted = User.query.filter_by(id=user_id).first()
    logger.debug('User {} is deleting user {}'.format(session['LOGINNAME'], user_tobe_deleted.username))
    if user_tobe_deleted.email == session['LOGINUSER']:
        flash('不能删除自己')
    else:
        if Role.query.filter_by(id=session['ROLE']).first().permissions < Role.query.filter_by(
                name='SNOC').first().permissions:
            logger.debug(session['ROLE'])
            flash('你没有权限删除他人账户')
        else:
            logger.info('try to delete {}:{}:{}'
                        .format(user_tobe_deleted.id, user_tobe_deleted.username, user_tobe_deleted.email))
            try:
                # 9 means deleted
                user_tobe_deleted.status = 9
                db.session.add(user_tobe_deleted)
                db.session.commit()
                logger.info('user is deleted')
                flash('用户删除成功')
            except Exception as e:
                logger.error('Delete user fail:{}'.format(e))
                flash('用户删除失败')

    return redirect(url_for('.local_user_check'))


@main.route('/areainfo_update', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def areainfo_update():
    area_id = request.form.get('area_id')
    area_name = request.form.get('area_name')
    area_desc_list = []
    area_machine_room = request.form.get('machine_room_name')
    logger.debug('area_name {} machine_room {}'.format(area_name, area_machine_room))
    if area_machine_room != 'null':
        area_machine_room = area_machine_room.split(',')
    logger.debug(area_machine_room)

    areainfo_tobe_updated = Area.query.filter_by(id=area_id).first()

    if areainfo_tobe_updated.area_machine_room == '0xffffffffff':
        return redirect(url_for('.area_config', update_result=3))

    if area_name:
        areainfo_tobe_updated.area_name = area_name

    if area_machine_room != 'null':
        logger.debug('area_machine_room {}'.format(area_machine_room))
        permit_machineroom = 0
        for mr in area_machine_room:
            permit_value = MachineRoom.query.filter_by(id=mr).first()
            area_desc_list.append(permit_value.name)
            if permit_value:
                permit_machineroom |= int(permit_value.permit_value, 16)

        areainfo_tobe_updated.area_machine_room = hex(permit_machineroom)

        logger.info('The hex of the permitted machine room is {}'.format(hex(permit_machineroom)))

        area_desc = ','.join(area_desc_list)
        areainfo_tobe_updated.area_desc = area_desc

    if area_name or area_machine_room:
        try:
            db.session.add(areainfo_tobe_updated)
            db.session.commit()
            logger.info('update area info successful')
            update_result = 1
        except Exception as e:
            logger.error(e)
            update_result = 2
    else:
        update_result = 4

    return redirect(url_for('.area_config', update_result=update_result))


@main.route('/gps_location', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def gps_location():
    return render_template('GPS.html')


@main.route('/syslog_config', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def syslog_config():
    if request.method == 'GET':
        logger.info('User {} is doing syslog config'.format(session['LOGINNAME']))
        return render_template('syslog_config.html')
    elif request.method == 'POST':
        draw = request.form.get('draw')
        page_start = int(request.form.get('start', '0'))
        length = int(request.form.get('length'))

        data = [[sc.id,
                 sc.alarm_type,
                 sc.alarm_level,
                 sc.alarm_name,
                 sc.alarm_keyword,
                 sc.alarm_status,
                 sc.create_time,
                 """<a data-toggle="modal" data-target="#update" onclick="editInfo(""" + str(sc.id) + """)">
                                              <img src="../static/edit.png" alt="" title=""
                                              border="0" /></a>""",
                 """<td><a onClick="return HTMerDel(""" + str(sc.id)
                 + """);"><img src="../static/trash.png" alt="" title="" border="0" /></a></td>"""
                 ]
                for sc in SyslogAlarmConfig.query.offset(page_start).limit(length)]

        recordsTotal = SyslogAlarmConfig.query.count()

        rest = {'draw': int(draw),
                'recordsTotal': recordsTotal,
                'recordsFiltered': recordsTotal,
                'data': data
                }
        return jsonify(rest)


@main.route('/syslog_config_add', methods=['POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def syslog_config_add():
    params = request.get_data()
    jl = params.decode('utf-8')
    j = json.loads(jl)
    print(j)
    syslog_type = j.get('syslog_type')
    syslog_alarm_level = j.get('syslog_alarm_level')
    syslog_alarm_name = j.get('syslog_alarm_name')
    syslog_alarm_keyword = j.get('syslog_alarm_keyword')

    if SyslogAlarmConfig.query.filter(or_(SyslogAlarmConfig.alarm_name.__eq__(syslog_alarm_name),
                                          SyslogAlarmConfig.alarm_keyword.__eq__(syslog_alarm_keyword))).all():
        return jsonify(json.dumps({'status': 'False'}))
    else:
        syslog_alarm_keyword = syslog_alarm_keyword.replace('\n', '\\n')
        print(syslog_alarm_keyword)
        new_config = SyslogAlarmConfig(alarm_type=syslog_type,
                                       alarm_name=syslog_alarm_name,
                                       alarm_level=syslog_alarm_level,
                                       alarm_status=1,
                                       alarm_keyword=syslog_alarm_keyword,
                                       create_time=time.localtime())
        db.session.add(new_config)
        db.session.commit()
        return jsonify(json.dumps({'status': 'OK'}))


@main.route('/syslog_config_delete', methods=['POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def syslog_config_delete():
    params = request.get_data()
    jl = params.decode('utf-8')
    j = json.loads(jl)
    print(j)
    sc_id = j.get('sc_id')

    delete_target = SyslogAlarmConfig.query.filter_by(id=sc_id).first()

    if delete_target:
        db.session.delete(delete_target)
        db.session.commit()
        return jsonify(json.dumps({'status': 'OK'}))
    else:
        return jsonify(json.dumps({'status': 'False'}))


@main.route('/test', methods=['GET', 'POST'])
def test():
    if request.method == 'GET':
        return render_template('test.html')
    elif request.method == 'POST':
        print(request.form.get('length'))
        recordsTotal = len(AlarmRecord.query.all())
        recordsFiltered = recordsTotal
        print(recordsTotal)
        draw = request.form.get('draw')
        print(draw)
        print(request.form.get('start'))
        page_start = int(request.form.get('start', '0'))
        page_end = page_start + int(request.form.get('length'))
        data = [[str(ui.id), ui.content, ui.create_time] for ui in AlarmRecord.query.all()]
        rest = {'draw': int(draw),
                'recordsTotal': recordsTotal,
                'recordsFiltered': recordsFiltered,
                'data': data[page_start:page_end],
                }
        return jsonify(rest)


@main.route('/syslog_search', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def syslog_search():
    device_list = {device.ip: device.device_name for device in Device.query.all()}
    if request.method == 'GET':
        syslog_ip = [[ip[0], ip[0] + '(' + str(device_list.get(ip[0])) + ')']
                     for ip in Syslog.query.with_entities(Syslog.device_ip).group_by(Syslog.device_ip).all()]

        sys_serverty = [value for value in syslog_serverty.values()]
        logger.info('User {} is checking syslog record'.format(session['LOGINNAME']))
        return render_template('syslog_search.html', syslog_ip=syslog_ip, sys_serverty=sys_serverty)
    elif request.method == 'POST':
        device_ip = '%' + request.form.get('device_ip', '') + '%'
        logmsg = '%' + request.form.get('logmsg', '') + '%'
        search_date = request.form.get('search_date')
        serverty = '%' + request.form.get('serverty', '') + '%'
        logger.debug('{} {} {} {}'.format(device_ip, logmsg, search_date, serverty))
        if search_date:
            start_time, stop_time = search_date.split(' - ')

            start_time = datetime.datetime.strptime(start_time + ' 00:00:00', '%Y-%m-%d %H:%M:%S') \
                if search_date else datetime.datetime(2000, 1, 1, 0, 0, 0)

            stop_time = datetime.datetime.strptime(stop_time + ' 23:59:59', '%Y-%m-%d %H:%M:%S') \
                if search_date else datetime.datetime(2100, 12, 31, 23, 59, 59)

            logger.debug('search syslog from {} to {}'.format(start_time, stop_time))

        draw = request.form.get('draw')
        page_start = int(request.form.get('start', '0'))
        length = int(request.form.get('length'))

        if request.form.get('device_ip') or request.form.get('logmsg') or search_date or request.form.get('serverty'):
            logger.debug('{} {} {} {} {}'.format(device_ip, logmsg, start_time, stop_time, serverty))
            logger.debug('search syslog')
            data = [[syslog.id,
                     device_list.get(syslog.device_ip),
                     syslog.device_ip,
                     syslog.logmsg,
                     syslog.serverty,
                     syslog.logtime]
                    for syslog in Syslog.query.filter(Syslog.device_ip.like(device_ip),
                                                      Syslog.logmsg.like(logmsg),
                                                      Syslog.logtime.between(start_time, stop_time),
                                                      Syslog.serverty.like(serverty)).order_by(
                    Syslog.logtime.desc()).offset(page_start).limit(length)]
            recordsTotal = Syslog.query.filter(Syslog.device_ip.like(device_ip),
                                               Syslog.logmsg.like(logmsg),
                                               Syslog.logtime.between(start_time, stop_time),
                                               Syslog.serverty.like(serverty)).count()
        else:
            data = [[syslog.id,
                     device_list.get(syslog.device_ip),
                     syslog.device_ip,
                     syslog.logmsg,
                     syslog.serverty,
                     syslog.logtime]
                    for syslog in Syslog.query.order_by(Syslog.logtime.desc()).offset(page_start).limit(length)]
            recordsTotal = Syslog.query.count()

        rest = {'draw': int(draw),
                'recordsTotal': recordsTotal,
                'recordsFiltered': recordsTotal,
                'data': data
                }
        return jsonify(rest)


@main.route('/licence_control', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def licence_control():
    expire_date, expire_in, pubkey = get_pubkey()
    expire_date = time.strftime('%Y-%m-%d', time.localtime(expire_date))
    pubkey = pubkey.replace('\n', '\r\n')
    return render_template('licence_control.html',
                           expire_date=expire_date,
                           expire_in=expire_in,
                           pubkey=pubkey)


@main.route('/params_config', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def params_config():
    wechat_config = get_config('wechat')
    callapi_config = get_config('callapi')
    scheduler_config = get_config('scheduler')
    alarmpolicy_config = get_config('alarmpolicy')
    cacti_config = get_config('Cacti')

    return render_template('params_config.html',
                           wechat_config=wechat_config,
                           callapi_config=callapi_config,
                           scheduler_config=scheduler_config,
                           alarmpolicy_config=alarmpolicy_config,
                           cacti_config=cacti_config)


@main.route('/update_config', methods=['POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def update_wechat_config():
    params = request.get_data()
    jl = params.decode('utf-8')
    j = json.loads(jl)
    logger.info('User {} is updating api configuration {}'.format(session['LOGINNAME'], j))

    api_params = j.get('api_params').strip()
    api_params_value = j.get('api_params_value').strip()
    api_name = j.get('api_name').strip()
    print(api_params_value)

    update_api_params = ApiConfigure.query.filter_by(api_name=api_name, api_params=api_params).first()

    update_api_params.api_params_value = api_params_value
    db.session.add(update_api_params)
    db.session.commit()

    return jsonify(json.dumps({'status': 'OK'}))


@main.route('/update_licence', methods=['POST'])
@login_required
@permission_required(Permission.ADMINISTER)
def update_licence():
    if update_crypted_licence(request.form.get('new_licence')):
        expire_date, expire_in, pubkey = get_pubkey()
        expire_date = time.strftime('%Y-%m-%d', time.localtime(expire_date))
        pubkey = pubkey.replace('\n', '\r\n')
        return jsonify(
            json.dumps({'status': 'OK', 'expire_date': expire_date, 'expire_in': expire_in, 'pubkey': pubkey}))
    else:
        return jsonify(json.dumps({'status': 'FAIL'}))


@main.route('/modify_scheduler_server', methods=['POST'])
def modify_scheduler_server():
    PermissionIP = ['127.0.0.1']
    if request.headers.get('X-Forwarded-For', request.remote_addr) not in PermissionIP:
        return jsonify(json.dumps({'status': 'Permission deny'}))
    logger.info('User {} is modifying scheduler configuration'.format(session['LOGINNAME']))
    params = request.get_data()
    jl = params.decode('utf-8')
    j = json.loads(jl)

    scheduler_id = j.get('scheduler_id')
    interval = float(j.get('interval').strip())
    try:
        if interval:
            scheduler.pause_job(id=scheduler_id)
            scheduler.modify_job(id=scheduler_id, trigger='interval', seconds=interval)
            scheduler.resume_job(id=scheduler_id)
            return jsonify(json.dumps({'status': '%s OK' % scheduler_id}))
        else:
            scheduler.pause_job(id=scheduler_id)
            return jsonify(json.dumps({'status': '%s 暂停' % scheduler_id}))
    except Exception as e:
        return jsonify(json.dumps({'status': '%s 提交计划任务失败' % scheduler_id}))


@main.route('/modify_scheduler', methods=['POST'])
@login_required
@permission_required(Permission.ADMINISTER)
def modify_scheduler():
    logger.info('User {} is modifying scheduler configuration'.format(session['LOGINNAME']))
    ms_url = "http://127.0.0.1:54322/modify_scheduler_server"
    params = request.get_data()

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json;charset=utf-8',
    }

    r = requests.post(ms_url, data=params, headers=headers)
    print(r.text)
    return r.text


@main.route('/update_callapi_config', methods=['POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def update_callapi_config():
    """
    此处默认权限为NETWORK_MANAGER,这样会造成网络管理员直接访问此路径能够具备修改微信接口和语音接口参数的权限,是个漏洞,需要修改
    :return:
    """
    logger.info('User {} is updating callapi configuration'.format(session['LOGINNAME']))
    params = request.get_data()
    jl = params.decode('utf-8')
    j = json.loads(jl)
    print(j)

    api_params = j.get('api_params').strip()
    api_params_value = j.get('api_params_value').strip()
    print(api_params_value)

    update_api_params = ApiConfigure.query.filter_by(api_name='callapi', api_params=api_params).first()

    update_api_params.api_params_value = api_params_value
    db.session.add(update_api_params)
    db.session.commit()

    return jsonify(json.dumps({'status': 'OK'}))


@main.route('/user_register', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def user_register():
    form = RegistrationForm()
    if form.validate_on_submit():
        logger.info('User {} is registering a new user:{}, email:{}, phoneNum: {}, role_id:{}, area:{}, duty:{}'.
                    format(session['LOGINNAME'],
                           form.username.data,
                           form.email.data,
                           form.phoneNum.data,
                           form.role.data,
                           form.area.data,
                           form.duty.data))
        machine_room_list = form.machine_room_name.data
        permit_machineroom = 0
        for mr in machine_room_list:
            permit_value = MachineRoom.query.filter_by(id=mr).first()
            if permit_value:
                permit_machineroom |= int(permit_value.permit_value, 16)

        logger.info('This new user {} permitted on machine room {}'.
                    format(form.username.data, hex(permit_machineroom)))

        try:
            user_role = Role.query.filter_by(id=form.role.data).first()
            user = User(username=form.username.data,
                        email=form.email.data,
                        phoneNum=form.phoneNum.data,
                        password=form.password.data,
                        role=user_role,
                        area=form.area.data,
                        duty=form.duty.data,
                        permit_machine_room=hex(permit_machineroom),
                        status=1)

            db.session.add(user)
            db.session.commit()
            logger.info('User {} register success'.format(form.username.data))
            flash('用户添加成功')
        except Exception as e:
            logger.error('user register {} fail for {}'.format(form.username.data, e))
            db.session.rollback()
            flash('用户添加失败, 请联系网管')
        return redirect(url_for('.user_register'))
    return render_template('user_register.html', form=form)


@main.route('/local_user_check', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def local_user_check():
    modal_form = UserModal()
    logger.info('User {} is checking user list'.format(session['LOGINNAME']))
    page = request.args.get('page', 1, type=int)
    flash_message = {1: '用户信息修改成功', 2: '用户信息修改失败', 3: '无权修改用户信息', 4: '未修改信息'}

    update_result = request.args.get('update_result')
    if update_result:
        session['update_result'] = update_result

    if session.get('update_result') and not update_result:
        flash(flash_message[int(session['update_result'])])
        session['update_result'] = ''

    POSTS_PER_PAGE = 10

    if page < 1:
        page = 1
    paginate = User.query.filter_by(status=1).order_by(User.id).paginate(page, POSTS_PER_PAGE, False)
    roles_name = {r.id: r.name for r in Role.query.all()}
    area_name = {a.id: a.area_name for a in Area.query.all()}

    object_list = paginate.items

    return render_template('local_user_check.html',
                           pagination=paginate,
                           object_list=object_list,
                           roles_name=roles_name,
                           area_name=area_name,
                           POSTS_PER_PAGE=POSTS_PER_PAGE,
                           modal_form=modal_form)


@main.route('/area_config', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def area_config():
    logger.info('User {} is checking area list'.format(session['LOGINNAME']))
    page = request.args.get('page', 1, type=int)
    update_result = request.args.get('update_result')
    flash_message = {1: '大区信息修改成功', 2: '大区信息修改失败', 3: '无权修改大区信息', 4: '未修改信息'}

    if update_result:
        session['update_result'] = update_result

    if session.get('update_result') and not update_result:
        flash(flash_message[int(session['update_result'])])
        session['update_result'] = ''
    form = AreaConfigForm()
    modal_form = AreaModal()

    if form.validate_on_submit():
        logger.info('User {} is configuring the machine room included in area {}'
                    .format(session['LOGINNAME'], form.area_machine_room.data, form.area_name.data))

        machine_room_list = form.area_machine_room.data
        permit_machineroom = 0
        area_desc_list = []
        for mr in machine_room_list:
            permit_value = MachineRoom.query.filter_by(id=mr).first()
            area_desc_list.append(permit_value.name)
            if permit_value:
                permit_machineroom |= int(permit_value.permit_value, 16)

        area_desc = ','.join(area_desc_list)
        logger.info('The hex of the permitted machine room is {}'.format(permit_machineroom))
        try:
            insert_area = Area(area_name=form.area_name.data,
                               area_desc=area_desc,
                               area_machine_room=hex(permit_machineroom))
            db.session.add(insert_area)
            db.session.commit()
            logger.info('Area config successful')
            flash('大区添加成功')
        except Exception as e:
            logger.error('config area fail for {}'.format(e))
            flash('插入数据失败')
        return redirect(url_for('.area_config'))

    POSTS_PER_PAGE = 10

    if page < 1:
        page = 1
    paginate = Area.query.order_by(Area.id).paginate(page, POSTS_PER_PAGE, False)

    object_list = paginate.items

    return render_template('area_config.html',
                           pagination=paginate,
                           object_list=object_list,
                           POSTS_PER_PAGE=POSTS_PER_PAGE,
                           form=form,
                           modal_form=modal_form)


@main.route('/userinfo_update', methods=['POST'])
@login_required
@permission_required(Permission.FOLLOW)
def userinfo_update():
    password = request.form.get('pass')
    username = request.form.get('username')
    area = request.form.get('area')
    role = request.form.get('role')
    duty = request.form.get('duty')
    id = request.form.get('id')
    phone_number = request.form.get('phone_number')

    logger.info('User {} is update {}\'s info'.format(session['LOGINNAME'], id))
    logger.debug('{password} {username} {area} {role} {duty} {id} {phone_number}'.format_map(vars()))
    if id == session.get('SELFID') or Role.query.filter_by(id=session['ROLE']).first().permissions >= 127:
        userinfo_tobe_changed = User.query.filter_by(id=id).first()

        if password:
            userinfo_tobe_changed.password = password
        if username:
            userinfo_tobe_changed.username = username
        if int(area) > 0:
            userinfo_tobe_changed.area = area
        if int(role) > 0:
            userinfo_tobe_changed.role_id = role
        if int(duty) > 0:
            userinfo_tobe_changed.duty = duty
        if phone_number:
            userinfo_tobe_changed.phoneNum = phone_number
        if password or username or phone_number or int(area) > 0 or int(role) > 0 or int(duty) > 0:
            try:
                db.session.add(userinfo_tobe_changed)
                db.session.commit()
                update_result = 1
                logger.info('Userinfo of user id {} is changed'.format(id))
            except Exception as e:
                update_result = 2
                logger.error('Userinfo change fail: {}'.format(e))
        else:
            update_result = 4
    else:
        logger.info('This user do not permitted to alter user info')
        update_result = 3
    return redirect(url_for('.local_user_check', update_result=update_result))


@main.route('/add_device', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def add_device():
    form = DeviceForm()
    if form.validate_on_submit():
        logger.info(
            'User {} add device on machine room {}'.format(session.get('LOGINNAME'), form.machine_room_name.data))
        try:
            device = Device(device_name=form.device_name.data,
                            ip=form.ip.data,
                            login_name='monitor',
                            login_password='shf-k61-906',
                            enable_password='',
                            machine_room=MachineRoom.query.filter_by(id=form.machine_room_name.data).first(),
                            status=form.status.data)
            db.session.add(device)
            db.session.commit()
            logger.info('User {} add device {}  in machine room {} successful'.
                        format(session.get('LOGINNAME'), form.device_name.data,
                               MachineRoom.query.filter_by(id=form.machine_room_name.data).first()))
            flash('Add Successful')
        except Exception as e:
            # 但是此处不能捕获异常
            logger.error('User {} add device {}  in machine room {} fail, because {}'.
                         format(session.get('LOGINNAME'), form.device_name.data,
                                MachineRoom.query.filter_by(id=form.machine_room_name.data).first(), e))
            flash('Add device fail')
        return redirect(url_for('.add_device'))
    return render_template('add_device.html', form=form)
