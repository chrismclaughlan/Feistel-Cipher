from feistel_cipher import feistel_cipher as fc
import unittest


class FeistelCipherTestCase(unittest.TestCase):

    def test_encode(self):
        set = {
            'keys': [
                ["qwertyuiop", "1234567890", "asdfghjkl"],
                ["1122334455, 6677889900"], ["123", "234"],
                ["123", "234", "345", "456", "567", "678", "789", "890"],
            ],
            'data': [
                "Hello World!",
                "I love to play with kittens. Kittens are my world!",
                "One Two Three four five six seven eight 9 10",
                "Milk Chocolate with Roasted Chopped Hazelnuts.\n 12323424"
                # "Ingredients: Sugar, Cocoa Butter, Dried Whole Milk, Cocoa "
                # "Mass, Chopped Hazelnuts (10%), Whey Powder (Milk)",
            ]
        }

        for i in range(len(set['keys'])):
        # for i in range(0, 3):
            cipher = fc.encode(set['data'][i], set['keys'][i])
            decoded = fc.decode(cipher, set['keys'][i])
            print("len=%d decoded=%s" % (len(decoded), decoded))
            self.assertEqual(set['data'][i], decoded)

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


if __name__ == '__main__':
    unittest.main()