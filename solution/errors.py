"""统一错误码与异常类型。

设计约束（来源隔离）：异常中携带的 ``path`` 只允许是**规格/策略里预先配置的
JSON Pointer 字符串**，绝不能是从实际事件数据里取到的键名或值。审计日志据此
保证不会泄露未授权枝的任何内容。
"""

# ---- 规格类错误：整版拒绝 ---------------------------------------------------
SPEC_EMPTY_COLUMNS = "SPEC_EMPTY_COLUMNS"            # 规格没有任何导出列
SPEC_COLUMN_NAME_CONFLICT = "SPEC_COLUMN_NAME_CONFLICT"  # 两个同名导出列
SPEC_DERIVED_CYCLE = "SPEC_DERIVED_CYCLE"            # 派生列之间存在环
SPEC_DEP_MISSING = "SPEC_DEP_MISSING"                # $引用的派生列不存在
SPEC_INVALID_POINTER = "SPEC_INVALID_POINTER"        # 规格中的指针语法非法
SPEC_INVALID_SOURCE = "SPEC_INVALID_SOURCE"          # 不允许的 source 形态/任意表达式
SPEC_INVALID_MASK = "SPEC_INVALID_MASK"              # mask 参数非法
SPEC_INVALID_CONCAT = "SPEC_INVALID_CONCAT"          # concat 参数非法
SPEC_INVALID_SORT = "SPEC_INVALID_SORT"              # 排序引用了不存在的列
SPEC_INVALID_META = "SPEC_INVALID_META"              # 规格元数据缺失/类型错误

# ---- 策略类错误 -------------------------------------------------------------
POLICY_INVALID_POINTER = "POLICY_INVALID_POINTER"    # 策略中的指针语法非法
POLICY_INVALID_STRUCTURE = "POLICY_INVALID_STRUCTURE"  # 策略结构非法
ROLE_UNKNOWN = "ROLE_UNKNOWN"                        # 快照绑定的角色不存在

# ---- 事件级授权错误 ---------------------------------------------------------
TENANT_DENIED = "TENANT_DENIED"                      # 角色未覆盖该租户
EVENT_TYPE_DENIED = "EVENT_TYPE_DENIED"              # 角色未授权该事件类型

# ---- 路径级授权错误（按解码后的段匹配）--------------------------------------
PATH_GLOBAL_BLOCKED = "PATH_GLOBAL_BLOCKED"          # 命中全局封锁（字典枝/容器）
PATH_ARRAY_BLOCKED = "PATH_ARRAY_BLOCKED"            # 数组整体被封锁或违规深入数组
PATH_NOT_AUTHORIZED = "PATH_NOT_AUTHORIZED"          # 角色未精确授权该原始路径

# ---- 取值/计算类错误 --------------------------------------------------------
POINTER_MISSING = "POINTER_MISSING"                  # 路径存在授权但事件中缺键
POINTER_TYPE = "POINTER_TYPE"                        # 穿过标量取值/类型不匹配
CONCAT_TYPE_ERROR = "CONCAT_TYPE_ERROR"              # concat 任一部分不是字符串
MASK_TYPE_ERROR = "MASK_TYPE_ERROR"                  # mask 作用对象不是字符串

ALL_CODES = frozenset(
    [
        SPEC_EMPTY_COLUMNS,
        SPEC_COLUMN_NAME_CONFLICT,
        SPEC_DERIVED_CYCLE,
        SPEC_DEP_MISSING,
        SPEC_INVALID_POINTER,
        SPEC_INVALID_SOURCE,
        SPEC_INVALID_MASK,
        SPEC_INVALID_CONCAT,
        SPEC_INVALID_SORT,
        SPEC_INVALID_META,
        POLICY_INVALID_POINTER,
        POLICY_INVALID_STRUCTURE,
        ROLE_UNKNOWN,
        TENANT_DENIED,
        EVENT_TYPE_DENIED,
        PATH_GLOBAL_BLOCKED,
        PATH_ARRAY_BLOCKED,
        PATH_NOT_AUTHORIZED,
        POINTER_MISSING,
        POINTER_TYPE,
        CONCAT_TYPE_ERROR,
        MASK_TYPE_ERROR,
    ]
)


class ExportError(Exception):
    """带稳定错误码的受控异常。

    :param code: 上述 ``*_*`` 常量之一
    :param path: 触发问题的**已配置** JSON Pointer 原文；事件级问题传 ``None``
    :param detail: 只允许描述结构性原因，禁止夹带事件中的实际键名/值
    """

    def __init__(self, code, path=None, detail=""):
        if code not in ALL_CODES:
            raise ValueError("未知错误码: %r" % code)
        self.code = code
        # 防御性断言：path 若给出必须是字符串（配置面原文），不允许是 dict/list
        if path is not None and not isinstance(path, str):
            raise ValueError("path 只能是配置面的指针字符串，收到 %r" % type(path))
        self.path = path
        self.detail = detail
        super().__init__("%s path=%s %s" % (code, path, detail))
