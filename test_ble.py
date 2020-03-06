import blescan

def test_parse_packet():
    pkt = b'\x04>*\x02\x01\x03\x01w\t\xbc\xd0W\xef\x1e\x02\x01\x04\x1a\xffL\x00\x02\x15\xa4\x95\xbb0\xc5\xb1KD\xb5\x12\x13p\xf0-t\xde\x00B\x03\xf7\xc5\xa7'

    assert blescan.parse_packet(pkt) == {
        'mac': '09:77:01:03:01:02',
        'uuid': 'a495bb30c5b14b44b5121370f02d74de',
        'major': 66,
        'minor': 1015
    }
