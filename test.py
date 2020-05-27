import feistel_cipher as fc
import unittest

KEYS = [
    ["qwertyuiop", "1234567890", "asdfghjkl"],
    ["1122334455, 6677889900"], ["123", "234"],
    ["123", "234", "345", "456", "567", "678", "789", "890"],
    ["123", "234", "345", "456", "567", "678", "789", "890"],
]

CLEARTEXT = [
    "Hello World!",
    "I love to play with kittens. Kittens are my world!",
    "One Two Three four five six seven eight 9 10",
    "Milk Chocolate with Roasted Chopped Hazelnuts.\n 12323424"
    "Ingredients: Sugar, Cocoa Butter, Dried Whole Milk, Cocoa "
    "Mass, Chopped Hazelnuts (10%), Whey Powder (Milk)",
    "What is Lorem Ipsum?\n"
    "Lorem Ipsum is simply dummy text of the printing and typesetting "
    "industry. Lorem Ipsum has been the industry's \nstandard dummy text ever "
    "since the 1500s, when an unknown printer took a galley of type and "
    "scrambled it to \nmake a type specimen book. It has survived not only "
    "five centuries, but also the leap into electronic \ntypesetting, remaining "
    "essentially unchanged. It was popularised in the 1960s with the release "
    "of Letraset \nsheets containing Lorem Ipsum passages, and more recently "
    "with desktop publishing software like Aldus PageMaker \nincluding versions "
    "of Lorem Ipsum."
]

class FeistelCipherTestCase(unittest.TestCase):

    def test_get_source_txt(self):
        self.maxDiff = None

        s1 = CLEARTEXT[4]
        s2 = fc.get_source_txt("resources\\text1.txt")
        self.assertEqual(s1, s2)

        cipher1 = fc.encode(s1, KEYS[0])
        cipher2 = fc.encode(s2, KEYS[1])
        print(f"\tcipher1 len[{len(cipher1)}]=" + cipher1)
        print(f"\tcipher2 len[{len(cipher2)}]=" + cipher2)
        cleartext1 = fc.decode(cipher1, KEYS[0])
        cleartext2 = fc.decode(cipher2, KEYS[1])
        print(f"\tcleartext1 len[{len(cleartext1)}]=" + cleartext1)
        print(f"\tcleartext2 len[{len(cleartext2)}]=" + cleartext2)
        self.assertEqual(s1, cleartext1)
        self.assertEqual(s2, cleartext2)


    def test_encode(self):
        for i in range(0, len(CLEARTEXT)):
            s = CLEARTEXT[i]
            k = KEYS[i]
            cipher = fc.encode(s, k)
            print(f"\tcipher len[{len(cipher)}]="+cipher)
            cleartext = fc.decode(cipher, k)
            print(f"\tcleartext len[{len(cleartext)}]="+cleartext)
            self.assertEqual(s, cleartext)


    def test_split_blocks(self):
        s1 = "Milk Chocolate with Roasted Chopped Hazelnuts.\n 12323424 " \
             "Ingredients: Sugar, Cocoa Butter, Dried Whole Milk, Cocoa " \
             "Mass, Chopped Hazelnuts (10%), Whey Powder (Milk)"
        n1 = 4
        result = fc.split_blocks(s1, n1)
        for block in result:
            self.assertEqual(len(block), n1)

    def test_pad_block(self):
        s1 = "This string is 28 bytes long"
        s2 = ""
        n = 64
        c = " "
        result = fc.pad_block(s1, n, c)
        self.assertEqual(len(result), n)
        result_padded = \
            "This string is 28 bytes long                                    "
        self.assertEqual(result, result_padded)
        self.assertRaises(fc.EncodeError, fc.pad_block, s2, n, c)
        self.assertRaises(fc.EncodeError, fc.pad_block, s1, 1, c)

    def test_split(self):
        data = "OEOEOEOEoeoeoeoe"

        left, right = fc.split(data)
        self.assertEqual(len(left), len(right))
        self.assertEqual(left, "OEOEOEOE")
        self.assertEqual(right, "oeoeoeoe")
        self.assertEqual(right, "oeoeoeoe")

    def test_create_salt(self):
        blocksT = [
            "This string is 64 bytes long301111111111111111111111111111111111",
        ]
        blocksF = [
            "This string is 28 bytes long",
        ]
        for each in blocksT:
            self.assertEqual(len(fc.create_salt(each.encode())), 16)
        for each in blocksF:
            self.assertRaises(fc.EncodeError, fc.create_salt, each.encode())

    # def test_encode_function(self):
    #     keys1 = ["key1", "key2", "key3",]
    #     keys2 = ["key3", "key2", "key1",]
    #     print("CLEARTEXT="+CLEARTEXT[0])
    #     cipher = fc.encode_function(CLEARTEXT[0], " ".join(keys1))
    #     print("CIPHER="+cipher)
    #     result = fc.encode_function(cipher, " ".join(keys2))
    #     print("RESULT="+result)

        # self.assertEqual(len(CLEARTEXT[0]), len(result))
        # s1 = "This string is longer than 64 bytes                           " \
        #      "                                                              !"
        # s2 = ""
        # self.assertRaises(fc.EncodeError, fc.encode_function, s1, " ".join(KEYS[0]))
        # self.assertRaises(fc.EncodeError, fc.encode_function, s2, " ".join(KEYS[0]))


    def test_parse_keys(self):
        keys = "fwnkjfn3wjkf hr83hrnr rnjnfj35i"

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