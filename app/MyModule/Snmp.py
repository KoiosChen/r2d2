from pysnmp.entity.rfc3413.oneliner import cmdgen


class Snmp(object):
    """A basic SNMP session"""
    def __init__(self,oid="sysDescr", Version=2):
        self.oid = oid
        self.version = Version - 1
        self.destHost = ''
        self.community = ''
        self.cg = cmdgen.CommandGenerator()

    def query(self):
        """Creates SNMP query session"""
        try:
            errorIndication, errorStatus, errorIndex, varBinds = self.cg.getCmd(
              cmdgen.CommunityData('netagent', self.community, self.version),
                cmdgen.UdpTransportTarget((self.destHost, 161)),
                self.oid
            )
            result = varBinds
        except Exception as err:
            print(err)
            result = None
        return result