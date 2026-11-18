"""版本化导出规格：校验、派生列分析与原始路径闭包。

列来源只允许三种**固定形态**，刻意不提供任意表达式能力：

* ``{"type": "pointer", "path": "/a/b"}`` —— JSON Pointer 取值
* ``{"type": "concat", "parts": [源...] }`` —— 按序连接字符串
* ``{"type": "mask", "path": "/a", "keep": 2, "side": "left", "char": "*"}``
  —— 定长掩码，固定引用一个源字段

“源”只允许三种固定形态：

* 以 ``/`` 开头的字符串 —— 原始 JSON Pointer
* 以 ``$`` 开头的字符串 —— 派生列引用（如 ``$other_col``，引用本视图另一导出列）
* ``{"literal": "..."}`` —— 固定连接字符串（常量，不引用任何数据，
  以此与“任意表达式”严格区分）
"""

from .errors import (
    ExportError,
    SPEC_COLUMN_NAME_CONFLICT,
    SPEC_DEP_MISSING,
    SPEC_DERIVED_CYCLE,
    SPEC_EMPTY_COLUMNS,
    SPEC_INVALID_CONCAT,
    SPEC_INVALID_MASK,
    SPEC_INVALID_META,
    SPEC_INVALID_POINTER,
    SPEC_INVALID_SORT,
    SPEC_INVALID_SOURCE,
)
from .pointer import parse_pointer

DERIVED_PREFIX = "$"
RAW_PREFIX = "/"


class Column:
    def __init__(self, raw, index):
        if not isinstance(raw, dict):
            raise ExportError(SPEC_INVALID_SOURCE, None, "列定义必须为对象（列序号 %d）" % index)
        self.index = index
        self.name = raw.get("name")
        if not isinstance(self.name, str) or not self.name:
            raise ExportError(SPEC_INVALID_META, None, "列 name 必须为非空字符串（列序号 %d）" % index)
        # 默认必需（fail-closed）；显式 required=false 才是可选列
        self.required = bool(raw.get("required", True))
        source = raw.get("source")
        if not isinstance(source, dict):
            raise ExportError(SPEC_INVALID_SOURCE, None, "列 %r 缺少 source 对象" % self.name)
        self.kind = source.get("type")
        self.raw_paths = []          # 本列直接引用的原始指针原文
        self.dep_names = []          # 本列引用的其他派生列名
        self.source_raw = source     # 保留配置原文，执行期使用

        if self.kind == "pointer":
            self._load_single_pointer(source)
        elif self.kind == "concat":
            self._load_concat(source)
        elif self.kind == "mask":
            self._load_mask(source)
        else:
            raise ExportError(
                SPEC_INVALID_SOURCE, None,
                "列 %r 的 source.type 仅支持 pointer/concat/mask" % self.name,
            )

    def _register_ref(self, ref):
        """登记 concat 的一个组成部分。

        允许：``/`` 前缀原始指针、``$`` 前缀派生引用、``{"literal": str}``
        固定字面量；其余任何形态一律拒绝（禁止任意表达式）。
        """
        if isinstance(ref, dict):
            if set(ref.keys()) != {"literal"} or not isinstance(ref["literal"], str):
                raise ExportError(
                    SPEC_INVALID_SOURCE, None,
                    "列 %r 的字面量组成必须为 {\"literal\": 字符串}" % self.name,
                )
            return
        if not isinstance(ref, str):
            raise ExportError(SPEC_INVALID_SOURCE, None, "列 %r 存在非法源引用" % self.name)
        if ref.startswith(DERIVED_PREFIX):
            dep = ref[len(DERIVED_PREFIX):]
            if not dep:
                raise ExportError(SPEC_INVALID_SOURCE, None, "列 %r 的派生引用名为空" % self.name)
            self.dep_names.append(dep)
            return
        # 空字符串是合法的根指针（RFC 6901），其余原始指针必须以 / 开头
        if ref == "":
            self.raw_paths.append(ref)
            return
        if not ref.startswith(RAW_PREFIX):
            raise ExportError(
                SPEC_INVALID_SOURCE, None,
                "列 %r 的源 %r 既非原始指针(/)也非派生引用($)，字面量须用 "
                "{\"literal\": ...} 形态，禁止任意表达式" % (self.name, ref),
            )
        # 语法校验：非法转义等指针问题明确报 SPEC_INVALID_POINTER
        parse_pointer(ref, SPEC_INVALID_POINTER)
        self.raw_paths.append(ref)

    def _load_single_pointer(self, source):
        path = source.get("path")
        if not isinstance(path, str):
            raise ExportError(SPEC_INVALID_SOURCE, None, "列 %r 的 pointer 缺少 path" % self.name)
        self._register_ref(path)

    def _load_concat(self, source):
        parts = source.get("parts")
        if not isinstance(parts, list) or not parts:
            raise ExportError(SPEC_INVALID_CONCAT, None, "列 %r 的 concat.parts 必须为非空数组" % self.name)
        for ref in parts:
            self._register_ref(ref)

    def _load_mask(self, source):
        path = source.get("path")
        if not isinstance(path, str):
            raise ExportError(SPEC_INVALID_MASK, None, "列 %r 的 mask 缺少 path" % self.name)
        keep = source.get("keep")
        if not isinstance(keep, int) or isinstance(keep, bool) or keep < 0:
            raise ExportError(SPEC_INVALID_MASK, None, "列 %r 的 mask.keep 必须为非负整数" % self.name)
        side = source.get("side", "left")
        if side not in ("left", "right"):
            raise ExportError(SPEC_INVALID_MASK, None, "列 %r 的 mask.side 仅支持 left/right" % self.name)
        char = source.get("char", "*")
        if not isinstance(char, str) or len(char) != 1:
            raise ExportError(SPEC_INVALID_MASK, None, "列 %r 的 mask.char 必须为单字符字符串" % self.name)
        self._register_ref(path)


class ViewSpec:
    """校验通过后的单一视图规格（含拓扑序与每列的传递原始路径闭包）。"""

    def __init__(self, raw):
        if not isinstance(raw, dict):
            raise ExportError(SPEC_INVALID_META, None, "视图规格必须为对象")
        self.spec_id = raw.get("spec_id")
        self.version = raw.get("version")
        self.event_type = raw.get("event_type")
        if not isinstance(self.spec_id, str) or not self.spec_id:
            raise ExportError(SPEC_INVALID_META, None, "spec_id 必须为非空字符串")
        if not isinstance(self.version, (str, int)):
            raise ExportError(SPEC_INVALID_META, None, "version 缺失或类型非法")
        if not isinstance(self.event_type, str) or not self.event_type:
            raise ExportError(SPEC_INVALID_META, None, "event_type 必须为非空字符串")

        columns_raw = raw.get("columns")
        if not isinstance(columns_raw, list) or not columns_raw:
            raise ExportError(SPEC_EMPTY_COLUMNS, None, "视图 %s 必须至少声明一个导出列" % self.spec_id)

        # 1) 同名冲突：两个同名导出列 -> 整版拒绝
        names = [c.get("name") for c in columns_raw if isinstance(c, dict)]
        seen = set()
        for name in names:
            if name in seen:
                raise ExportError(SPEC_COLUMN_NAME_CONFLICT, None, "导出列重名: %r" % name)
            seen.add(name)

        self.columns = {}
        self.column_order = []
        for index, col_raw in enumerate(columns_raw):
            col = Column(col_raw, index)
            self.columns[col.name] = col
            self.column_order.append(col.name)

        # 2) 缺依赖：$引用了不存在的列 -> 整版拒绝
        for col in self.columns.values():
            for dep in col.dep_names:
                if dep not in self.columns:
                    raise ExportError(
                        SPEC_DEP_MISSING, None,
                        "列 %r 引用了不存在的派生列 %r" % (col.name, dep),
                    )

        # 3) 派生环：DFS 三色标记 -> 整版拒绝
        self.topo_order = self._topological_sort()

        # 4) 传递原始路径闭包（自身 raw_paths + 依赖列闭包）
        # 顺序语义：按指针文本排序后去重，给出与声明顺序无关的稳定闭包，
        # 授权检查逐路径进行，顺序不影响安全结论。
        self.transitive_raw = {}
        for name in self.topo_order:
            col = self.columns[name]
            closure = list(col.raw_paths)
            for dep in col.dep_names:
                closure.extend(self.transitive_raw[dep])
            self.transitive_raw[name] = tuple(sorted(frozenset(closure)))

        # 5) 排序配置（只允许引用已声明的列）
        self.sort = self._load_sort(raw.get("sort", []))

    def _topological_sort(self):
        WHITE, GRAY, BLACK = 0, 1, 2
        color = {name: WHITE for name in self.column_order}
        order = []

        def visit(name, stack):
            if color[name] == GRAY:
                cycle = " -> ".join(stack[stack.index(name):] + [name])
                raise ExportError(SPEC_DERIVED_CYCLE, None, "派生列引用存在环: %s" % cycle)
            if color[name] == BLACK:
                return
            color[name] = GRAY
            stack.append(name)
            for dep in self.columns[name].dep_names:
                visit(dep, stack)
            stack.pop()
            color[name] = BLACK
            order.append(name)

        for name in self.column_order:
            visit(name, [])
        return order

    def _load_sort(self, sort_raw):
        if not isinstance(sort_raw, list):
            raise ExportError(SPEC_INVALID_SORT, None, "sort 必须为数组")
        sort = []
        for item in sort_raw:
            if not isinstance(item, dict) or not isinstance(item.get("column"), str):
                raise ExportError(SPEC_INVALID_SORT, None, "sort 项必须包含 column 字符串")
            column = item["column"]
            if column not in self.columns:
                raise ExportError(SPEC_INVALID_SORT, None, "sort 引用了不存在的列 %r" % column)
            direction = item.get("direction", "asc")
            if direction not in ("asc", "desc"):
                raise ExportError(SPEC_INVALID_SORT, None, "sort.direction 仅支持 asc/desc")
            sort.append((column, direction))
        return sort
