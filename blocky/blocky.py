
from dns import resolver

class DetectIPAddresses(object):

    def __init__(self, fqdn='youtube.com'):
        self.fqdn = fqdn
        self._rslv = resolver.Resolver()

    def iplist(self):
        return [x.address for x in self._rslv.query(self.fqdn, 'A')]


if __name__ == '__main__':
    det = DetectIPAddresses()
    print det.iplist()

