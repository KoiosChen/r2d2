from .. import db, logger
from ..MyModule import AlarmPolicy, GetData, GetCactiPic


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
                             ', IP: ' + info['hostname'] + '\n\n')

    catalog2 = ('id', 'name', 'thold_hi', 'thold_low', 'thold_alert', 'host_id', 'graph_id', 'rra_id')
    thold_alert = getdata.get_result(query='thold_alert', catalog=catalog2)

    for alert in thold_alert:
        pic_url = GetCactiPic.get_cacti_pic(action='cacti_view_pic_url',
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