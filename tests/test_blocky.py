#!/usr/bin/env python

import unittest
import sys
import os

from blocky.blocky import DetectIPAddresses


class TestBlocky(unittest.TestCase):

    def test_detectipaddresses(self):
        det = DetectIPAddresses(fqdns=['localhost'])
        addr = det.iplist()
        self.assertEqual(addr, ['127.0.0.1'])

if __name__ == '__main__':
    unittest.main()