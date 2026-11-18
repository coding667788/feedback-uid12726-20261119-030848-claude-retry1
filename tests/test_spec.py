"""规格校验测试：同名冲突、派生环、缺依赖整版拒绝；闭包独立计算核对。"""

import unittest

from solution.errors import (
    ExportError,
    SPEC_COLUMN_NAME_CONFLICT,
    SPEC_DEP_MISSING,
    SPEC_DERIVED_CYCLE,
    SPEC_EMPTY_COLUMNS,
    SPEC_INVALID_POINTER,
    SPEC_INVALID_SORT,
    SPEC_INVALID_SOURCE,
)
from solution.spec import ViewSpec


def _pointer_col(name, path, required=True):
    return {"name": name, "required": required,
            "source": {"type": "pointer", "path": path}}


class TestSpecRejection(unittest.TestCase):
    def _base(self, columns, spec_id="s"):
        return {"spec_id": spec_id, "version": "v1",
                "event_type": "order.created", "columns": columns}

    def test_empty_columns_rejected(self):
        with self.assertRaises(ExportError) as ctx:
            ViewSpec(self._base([]))
        self.assertEqual(ctx.exception.code, SPEC_EMPTY_COLUMNS)

    def test_duplicate_column_names_rejected(self):
        spec = self._base([_pointer_col("c1", "/a"), _pointer_col("c1", "/b")])
        with self.assertRaises(ExportError) as ctx:
            ViewSpec(spec)
        self.assertEqual(ctx.exception.code, SPEC_COLUMN_NAME_CONFLICT)

    def test_direct_and_indirect_cycles_rejected(self):
        direct = self._base([
            {"name": "a", "source": {"type": "concat", "parts": ["$b"]}},
            {"name": "b", "source": {"type": "concat", "parts": ["$a"]}},
        ])
        with self.assertRaises(ExportError) as ctx:
            ViewSpec(direct)
        self.assertEqual(ctx.exception.code, SPEC_DERIVED_CYCLE)

        longer = self._base([
            {"name": "a", "source": {"type": "concat", "parts": ["$b"]}},
            {"name": "b", "source": {"type": "concat", "parts": ["$c"]}},
            {"name": "c", "source": {"type": "concat", "parts": ["$a"]}},
        ])
        with self.assertRaises(ExportError) as ctx:
            ViewSpec(longer)
        self.assertEqual(ctx.exception.code, SPEC_DERIVED_CYCLE)

    def test_missing_dependency_rejected(self):
        spec = self._base([
            {"name": "a", "source": {"type": "concat", "parts": ["$ghost", "/x"]}},
        ])
        with self.assertRaises(ExportError) as ctx:
            ViewSpec(spec)
        self.assertEqual(ctx.exception.code, SPEC_DEP_MISSING)

    def test_invalid_pointer_rejected(self):
        # 无前导 /：结构性来源错误
        with self.assertRaises(ExportError) as ctx:
            ViewSpec(self._base([_pointer_col("a", "no-leading-slash")]))
        self.assertEqual(ctx.exception.code, SPEC_INVALID_SOURCE)
        # 有前导 / 但转义非法：明确的指针语法错误
        with self.assertRaises(ExportError) as ctx:
            ViewSpec(self._base([_pointer_col("a", "/bad~2escape")]))
        self.assertEqual(ctx.exception.code, SPEC_INVALID_POINTER)

    def test_arbitrary_expression_forbidden(self):
        # 裸字符串表达式、未知 source 类型、非字面量对象都必须拒绝
        bad_sources = [
            {"type": "concat", "parts": ["plain-text"]},
            {"type": "eval", "expr": "1+1"},
            {"type": "concat", "parts": [{"value": "x"}]},
        ]
        for source in bad_sources:
            with self.subTest(source=source):
                with self.assertRaises(ExportError) as ctx:
                    ViewSpec(self._base([{"name": "a", "source": source}]))
                self.assertEqual(ctx.exception.code, SPEC_INVALID_SOURCE)

    def test_sort_unknown_column_rejected(self):
        spec = self._base([_pointer_col("a", "/a")])
        spec["sort"] = [{"column": "ghost", "direction": "asc"}]
        with self.assertRaises(ExportError) as ctx:
            ViewSpec(spec)
        self.assertEqual(ctx.exception.code, SPEC_INVALID_SORT)


class TestTopologyAndClosure(unittest.TestCase):
    def test_topo_order_respects_dependencies(self):
        spec = ViewSpec({
            "spec_id": "s", "version": 1, "event_type": "order.created",
            "columns": [
                # 声明顺序故意倒置：c 依赖 b，b 依赖 a
                {"name": "c", "source": {"type": "concat", "parts": ["$b", "/z"]}},
                {"name": "b", "source": {"type": "concat", "parts": ["$a", "/y"]}},
                {"name": "a", "source": {"type": "pointer", "path": "/x"}},
            ],
        })
        # 独立判定：依赖必须先于被依赖者
        position = {name: i for i, name in enumerate(spec.topo_order)}
        self.assertLess(position["a"], position["b"])
        self.assertLess(position["b"], position["c"])

    def test_transitive_raw_closure_independently_derived(self):
        spec = ViewSpec({
            "spec_id": "s", "version": 1, "event_type": "order.created",
            "columns": [
                _pointer_col("a", "/p1"),
                _pointer_col("b", "/p2"),
                {"name": "c", "source": {"type": "concat",
                                          "parts": ["$a", {"literal": "-"}, "$b", "/p3"]}},
                {"name": "d", "source": {"type": "concat", "parts": ["$c", "/p4"]}},
            ],
        })
        # 期望闭包按规格定义人工列出（不是调用实现计算）
        expected = {
            "a": ("/p1",),
            "b": ("/p2",),
            "c": ("/p1", "/p2", "/p3"),
            "d": ("/p1", "/p2", "/p3", "/p4"),
        }
        self.assertEqual(dict(spec.transitive_raw), expected)

    def test_literal_is_not_a_raw_path(self):
        spec = ViewSpec({
            "spec_id": "s", "version": 1, "event_type": "order.created",
            "columns": [
                {"name": "g", "source": {"type": "concat",
                                          "parts": [{"literal": "const"}, "/only"]}},
            ],
        })
        self.assertEqual(spec.transitive_raw["g"], ("/only",))


if __name__ == "__main__":
    unittest.main()
