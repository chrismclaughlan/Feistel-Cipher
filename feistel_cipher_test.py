import unittest

import feistel_cipher as fc


class FeistelCipherTestCase(unittest.TestCase):
    def test_split(self):
        data = "OEOEOEOEoeoeoeoe"

        left, right = fc.split(data)
        self.assertEqual(len(left), len(right))
        self.assertEqual(left, "OEOEOEOE")
        self.assertEqual(right, "oeoeoeoe")
        self.assertEqual(right, "oeoeoeoe")

    def test_parse_keys(self):
        keys = "fwnkjfn3wjkf-hr83hrnr-rnjnfj35i"

        keys = fc.parse_keys(keys)
        self.assertEqual(keys[0], "fwnkjfn3wjkf")
        self.assertEqual(keys[1], "hr83hrnr")
        self.assertEqual(keys[2], "rnjnfj35i")

    def test_xor_string(self):
        s1 = "e "  # 105 32
        s2 = "He"  # 72  101
        self.assertEqual(fc.xor_string(s1, s2), "-E")


    def test_encoding(self):
        pass
        #encoding = fc.encode("OEOEOEOEOE", ["key1", "key2", "key3"])
        #self.assertEqual(encoding, "")


if __name__ == '__main__':
    unittest.main()