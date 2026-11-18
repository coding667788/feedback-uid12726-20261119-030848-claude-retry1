"""RFC 6901 JSON Pointer 解析与取值。

关键安全语义
------------
1. 授权/封锁匹配一律使用**解码后的段元组**（``~1`` -> ``/``、``~0`` -> ``~``），
   编码歧义不能用来绕过封锁。
2. 数组只允许**整体读取**：指针一旦进入数组（在数组节点上还有剩余段），
   由调用方按 :data:`~solution.errors.PATH_ARRAY_BLOCKED` 拒绝；本模块在取值阶段
   也会以 :data:`~solution.errors.POINTER_TYPE` 给出结构性失败。
3. 段是 ``"01"`` 这类键时按普通对象键处理，不会被解释成数组下标——数字字典键
   与数组下标由运行时容器类型严格区分。
"""

from .errors import ExportError, POINTER_MISSING, POINTER_TYPE, SPEC_INVALID_POINTER


def parse_pointer(pointer, invalid_code=SPEC_INVALID_POINTER):
    """把 JSON Pointer 原文解析为**解码后**的段元组。

    :param pointer: 指针原文，必须是字符串且以 ``""`` 或 ``"/"`` 开头
    :param invalid_code: 语法非法时使用的错误码（规格面/策略面可区分）
    :returns: tuple[str, ...]；空指针返回 ``()``
    :raises ExportError: 指针不是字符串、不以 / 开头、含非法转义
    """
    if not isinstance(pointer, str):
        raise ExportError(invalid_code, None, "JSON Pointer 必须为字符串")
    if pointer and not pointer.startswith("/"):
        raise ExportError(invalid_code, pointer, "JSON Pointer 必须为 '' 或以 '/' 开头的字符串")
    if pointer == "":
        return ()
    raw_segments = pointer.split("/")[1:]
    decoded = []
    for raw in raw_segments:
        # RFC 6901：先 ~1 后 ~0；出现孤立的 ~（后不接 0/1）即非法转义
        idx = 0
        chars = []
        while idx < len(raw):
            ch = raw[idx]
            if ch == "~":
                if idx + 1 >= len(raw) or raw[idx + 1] not in ("0", "1"):
                    raise ExportError(invalid_code, pointer, "非法转义: 波浪号后必须为 0 或 1")
                chars.append("/" if raw[idx + 1] == "1" else "~")
                idx += 2
            else:
                chars.append(ch)
                idx += 1
        decoded.append("".join(chars))
    return tuple(decoded)


def is_prefix(prefix, segments):
    """``prefix`` 是否为 ``segments`` 的路径前缀（按解码段逐段相等）。"""
    if len(prefix) > len(segments):
        return False
    return all(prefix[i] == segments[i] for i in range(len(prefix)))


def resolve(container, segments):
    """在已解析的事件 JSON 上按段取值。

    前置条件：调用方已经完成授权判定。本函数只负责结构性取值，
    且不会把任何实际键名/值放进异常（异常只携带配置面指针原文由调用方附加）。

    :raises ExportError:
        * :data:`POINTER_MISSING` —— 字典缺键，或数组下标越界
        * :data:`POINTER_TYPE` —— 穿过标量取值、数字段用于字典、
          非数字段用于数组、在数组上继续深入（数组仅整体读取）
    """
    current = container
    for depth, segment in enumerate(segments):
        if isinstance(current, list):
            # 数组只允许整体读取：能进到这里说明指针进入了数组
            raise ExportError(POINTER_TYPE, None, "数组仅允许整体读取，禁止进入数组内部")
        if isinstance(current, dict):
            if segment not in current:
                raise ExportError(POINTER_MISSING, None, "字典缺少配置路径对应的键")
            current = current[segment]
        else:
            # 标量无法继续穿透
            raise ExportError(POINTER_TYPE, None, "试图穿过标量继续取值")
    return current


def encode_segments(segments):
    """把解码段重新编码为规范指针原文（用于审计展示，仍属配置面数据）。"""
    if not segments:
        return ""
    parts = []
    for seg in segments:
        parts.append(seg.replace("~", "~0").replace("/", "~1"))
    return "/" + "/".join(parts)
