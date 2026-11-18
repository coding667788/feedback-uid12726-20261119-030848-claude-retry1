"""JSON Pointer 解析与取值测试。

期望值按 RFC 6901 规则手工给出，不引用 solution.pointer 的内部逻辑。
"""

import unittest

from solution.errors import ExportError, POINTER_MISSING, POINTER_TYPE, SPEC_INVALID_POINTER
from solution.pointer import encode_segments, is_prefix, parse_pointer, resolve


class TestParsePointer(unittest.TestCase):
    def test_manual_segment_table(self):
        # 手工表：输入原文 -> 期望解码段（依据 RFC6901: ~1->/, ~0->~）
        table = [
            ("", ()),
            ("/", ("",)),
            ("/a", ("a",)),
            ("/a/b", ("a", "b")),
            ("/a~1b", ("a/b",)),
            ("/a~0b", ("a~b",)),
            # 双重转义与顺序：先解 ~1 再解 ~0
            ("/~01", ("~1",)),
            ("/~00", ("~0",)),
            ("/~1~0", ("/~",)),
            # 数字字典键也是普通字符串段
            ("/items/0/sku", ("items", "0", "sku")),
            # 前导零不是合法下标词法，但仍是合法指针段（按对象键处理）
            ("/01", ("01",)),
            ("/a//b", ("a", "", "b")),
        ]
        for raw, expected in table:
            with self.subTest(raw=raw):
                self.assertEqual(parse_pointer(raw), expected)

    def test_invalid_pointers(self):
        bad = ["a", "a/b", "/a~2", "/a~", "/~2"]
        for raw in bad:
            with self.subTest(raw=raw):
                with self.assertRaises(ExportError) as ctx:
                    parse_pointer(raw)
                self.assertEqual(ctx.exception.code, SPEC_INVALID_POINTER)
        # 非字符串输入属于结构性类型错误
        for raw in [123, None]:
            with self.subTest(raw=raw):
                with self.assertRaises(ExportError) as ctx:
                    parse_pointer(raw)
                self.assertEqual(ctx.exception.code, SPEC_INVALID_POINTER)
                self.assertIsNone(ctx.exception.path)

    def test_prefix_uses_decoded_segments(self):
        # 编码不同但解码后同段：前缀判定必须按解码结果
        decoded = parse_pointer("/a~1b/c")
        self.assertTrue(is_prefix(("a/b",), decoded))
        self.assertTrue(is_prefix(("a/b", "c"), decoded))
        self.assertFalse(is_prefix(("a/b", "c", "d"), decoded))
        self.assertFalse(is_prefix(("a",), decoded))

    def test_encode_roundtrip(self):
        for raw in ["", "/a/b", "/a~1b", "/~01", "/items/0/sku"]:
            self.assertEqual(encode_segments(parse_pointer(raw)), raw)


class TestResolve(unittest.TestCase):
    def setUp(self):
        # 独立构造的测试数据
        self.doc = {
            "a": {"b": 10, "nullish": None, "list": [1, 2, 3]},
            "0": {"nested": "dict-zero"},
            "s": "scalar",
        }

    def test_resolve_manual_values(self):
        cases = [
            ((), self.doc),
            (("a",), {"b": 10, "nullish": None, "list": [1, 2, 3]}),
            (("a", "b"), 10),
            # 已授权的 null：取到 None，不报错
            (("a", "nullish"), None),
            # 数字字典键：dict 上的 "0" 是普通键
            (("0", "nested"), "dict-zero"),
            # 数组整体读取：取整个 list，不报错
            (("a", "list"), [1, 2, 3]),
        ]
        for segments, expected in cases:
            with self.subTest(segments=segments):
                self.assertEqual(resolve(self.doc, segments), expected)

    def test_missing_key(self):
        with self.assertRaises(ExportError) as ctx:
            resolve(self.doc, ("a", "nope"))
        self.assertEqual(ctx.exception.code, POINTER_MISSING)

    def test_enter_array_rejected(self):
        # 进入数组内部 -> 类型错误（数组仅整体读取）
        with self.assertRaises(ExportError) as ctx:
            resolve(self.doc, ("a", "list", "0"))
        self.assertEqual(ctx.exception.code, POINTER_TYPE)

    def test_passthrough_scalar_rejected(self):
        with self.assertRaises(ExportError) as ctx:
            resolve(self.doc, ("s", "x"))
        self.assertEqual(ctx.exception.code, POINTER_TYPE)

    def test_numeric_segment_on_dict_is_plain_key(self):
        # 段 "0" 在 dict 上按键查，不会被当作下标
        self.assertEqual(resolve(self.doc, ("0",)), {"nested": "dict-zero"})

    def test_escaped_numeric_like_dict_key(self):
        # 键名含转义字符（如 "~0" 解码为 "~"）：永远是字典键，不参与数组词法
        doc = {"0": "plain-zero", "~0": "tilde-key", "a/b": "slash-key"}
        self.assertEqual(resolve(doc, parse_pointer("/~00")), "tilde-key")
        self.assertEqual(resolve(doc, parse_pointer("/a~1b")), "slash-key")
        # 前导零段 "01" 也是普通字典键
        doc2 = {"01": "leading-zero-key"}
        self.assertEqual(resolve(doc2, ("01",)), "leading-zero-key")


if __name__ == "__main__":
    unittest.main()
