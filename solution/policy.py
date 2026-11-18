"""策略面：角色授权与全局封锁判定。

授权模型（fail-closed，默认拒绝）
--------------------------------
1. **全局封锁优先**：任何角色授权都不能绕过封锁；封锁按**解码后的段**匹配，
   支持三种命中关系——相等、封锁路径是请求路径的前缀（封锁了某个后代枝）、
   请求路径是封锁路径的前缀（读取包含被封锁后代的容器）。
2. **数组仅整体读取**：请求路径在实际事件中进入某个数组（数组节点上还有剩余
   段）即 :data:`PATH_ARRAY_BLOCKED`；数组的任一子路径被封锁，整个数组的读取
   同样按 :data:`PATH_ARRAY_BLOCKED` 拒绝。
3. **角色授权为精确匹配**：角色只持有明确列出的原始路径，没有前缀继承，
   不匹配即 :data:`PATH_NOT_AUTHORIZED`。
4. 封锁判定先于角色判定，且不依赖键是否真实存在——未授权枝的存在性不可探测。
"""

from .errors import (
    EVENT_TYPE_DENIED,
    ExportError,
    PATH_ARRAY_BLOCKED,
    PATH_GLOBAL_BLOCKED,
    PATH_NOT_AUTHORIZED,
    POLICY_INVALID_POINTER,
    POLICY_INVALID_STRUCTURE,
    ROLE_UNKNOWN,
    TENANT_DENIED,
)
from .pointer import is_prefix, parse_pointer


class Policy:
    """解析后的不可变策略快照。"""

    def __init__(self, raw):
        if not isinstance(raw, dict):
            raise ExportError(POLICY_INVALID_STRUCTURE, None, "policy 必须为对象")
        self.policy_id = raw.get("policy_id")
        self.version = raw.get("version")
        if not isinstance(self.policy_id, str) or not self.policy_id:
            raise ExportError(POLICY_INVALID_STRUCTURE, None, "policy_id 缺失或非字符串")
        if not isinstance(self.version, (str, int)):
            raise ExportError(POLICY_INVALID_STRUCTURE, None, "version 缺失")

        self.roles = {}
        roles = raw.get("roles")
        if not isinstance(roles, dict) or not roles:
            raise ExportError(POLICY_INVALID_STRUCTURE, None, "roles 必须为非空对象")
        for role_name, role_raw in roles.items():
            self.roles[role_name] = self._build_role(role_name, role_raw)

        self.blocks = []  # [(event_type_or_None, 解码段元组, 指针原文)]
        blocks = raw.get("global_blocks", [])
        if not isinstance(blocks, list):
            raise ExportError(POLICY_INVALID_STRUCTURE, None, "global_blocks 必须为数组")
        for block in blocks:
            if not isinstance(block, dict) or not isinstance(block.get("path"), str):
                raise ExportError(POLICY_INVALID_STRUCTURE, None, "封锁项必须包含字符串 path")
            et = block.get("event_type")
            if et is not None and not isinstance(et, str):
                raise ExportError(POLICY_INVALID_STRUCTURE, None, "封锁项 event_type 必须为字符串")
            segments = parse_pointer(block["path"], POLICY_INVALID_POINTER)
            self.blocks.append((et, segments, block["path"]))

    @staticmethod
    def _build_role(role_name, role_raw):
        if not isinstance(role_raw, dict):
            raise ExportError(POLICY_INVALID_STRUCTURE, None, "角色 %r 配置必须为对象" % role_name)
        tenants = role_raw.get("tenants")
        if tenants is not None and (
            not isinstance(tenants, list) or not all(isinstance(t, str) for t in tenants)
        ):
            raise ExportError(POLICY_INVALID_STRUCTURE, None, "角色 tenants 必须为字符串数组")
        event_types = role_raw.get("event_types")
        if not isinstance(event_types, list) or not all(
            isinstance(e, str) for e in event_types
        ):
            raise ExportError(POLICY_INVALID_STRUCTURE, None, "角色 event_types 必须为字符串数组")
        paths_raw = role_raw.get("paths", {})
        if not isinstance(paths_raw, dict):
            raise ExportError(POLICY_INVALID_STRUCTURE, None, "角色 paths 必须为对象")
        paths = {}
        for et, pointers in paths_raw.items():
            if not isinstance(pointers, list) or not all(isinstance(p, str) for p in pointers):
                raise ExportError(POLICY_INVALID_STRUCTURE, None, "角色 paths 的值必须为字符串数组")
            paths[et] = frozenset(parse_pointer(p, POLICY_INVALID_POINTER) for p in pointers)
        return {
            "tenants": None if tenants is None else frozenset(tenants),
            "event_types": frozenset(event_types),
            "paths": paths,
        }

    # ---- 事件级判定 --------------------------------------------------------

    def check_event(self, role_name, tenant, event_type):
        """租户 + 事件类型门槛；失败抛事件级异常（无路径，不触达事件内容）。"""
        role = self.roles.get(role_name)
        if role is None:
            raise ExportError(ROLE_UNKNOWN, None, "角色在策略快照中不存在")
        if role["tenants"] is not None and tenant not in role["tenants"]:
            raise ExportError(TENANT_DENIED, None, "角色租户范围不包含该租户")
        if event_type not in role["event_types"]:
            raise ExportError(EVENT_TYPE_DENIED, None, "角色未授权该事件类型")
        return role

    # ---- 路径级判定 --------------------------------------------------------

    def check_path(self, role, event_type, segments, pointer_text, event):
        """判定一个**已配置**原始路径对当前事件是否可读。

        :param segments: 规格侧已解析的解码段元组
        :param pointer_text: 规格中的指针原文，仅供异常/审计原样回写
        :param event: 实际事件（仅用于判断容器是否为数组，不取值不外泄）
        """
        # 1) 全局封锁优先（按解码段匹配）
        self._check_global_blocks(event_type, segments, pointer_text, event)
        # 2) 数组整体读取约束（即使没有配置封锁也成立）
        if _enters_array(event, segments):
            raise ExportError(PATH_ARRAY_BLOCKED, pointer_text, "数组仅允许整体读取")
        # 3) 角色精确授权
        allowed = role["paths"].get(event_type, frozenset())
        if segments not in allowed:
            raise ExportError(PATH_NOT_AUTHORIZED, pointer_text, "角色未精确授权该原始路径")

    def _check_global_blocks(self, event_type, segments, pointer_text, event):
        for block_et, block_seg, block_text in self.blocks:
            if block_et is not None and block_et != event_type:
                continue
            if block_seg == segments:
                node = _safe_lookup(event, segments)
                code = PATH_ARRAY_BLOCKED if isinstance(node, list) else PATH_GLOBAL_BLOCKED
                raise ExportError(code, pointer_text, "命中全局封锁: %s" % block_text)
            if is_prefix(block_seg, segments):
                # 封锁了请求路径的某个后代枝
                node = _safe_lookup(event, block_seg)
                code = PATH_ARRAY_BLOCKED if isinstance(node, list) else PATH_GLOBAL_BLOCKED
                raise ExportError(code, pointer_text, "命中全局封锁（后代枝）: %s" % block_text)
            if is_prefix(segments, block_seg):
                # 读取的容器内含被封锁后代：容器本身也不可读，避免整包带出
                node = _safe_lookup(event, segments)
                code = PATH_ARRAY_BLOCKED if isinstance(node, list) else PATH_GLOBAL_BLOCKED
                raise ExportError(code, pointer_text, "命中全局封锁（容器内含封锁枝）: %s" % block_text)


def _safe_lookup(event, segments):
    """沿段查看节点类型；任何结构问题都返回 None（存在性不可被探测）。"""
    current = event
    for segment in segments:
        if isinstance(current, dict):
            if segment not in current:
                return None
            current = current[segment]
        elif isinstance(current, list):
            # 调用方语义已保证数组深入会被拒；这里仅做类型保守判断
            return current
        else:
            return None
    return current


def _enters_array(event, segments):
    """请求路径是否在实际事件中进入了数组（数组节点后仍有段）。"""
    current = event
    for depth, segment in enumerate(segments):
        if isinstance(current, list):
            return True  # 数组节点上仍有剩余段
        if isinstance(current, dict):
            if segment not in current:
                return False  # 缺失：交由取值阶段报 POINTER_MISSING
            current = current[segment]
        else:
            return False
    return False
