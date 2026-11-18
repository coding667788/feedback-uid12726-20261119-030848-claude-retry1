"""快照化离线导出引擎。

单次导出把输入事件、角色与策略版本、规格版本固定为一个快照；执行期不再读取
任何外部状态。所有错误/审计信息只引用**规格中已配置**的路径与稳定原因码，
实际事件里未授权的键名、值、内容摘要一律不进入输出。
"""

import copy
import hashlib
import json

from .errors import CONCAT_TYPE_ERROR, ExportError, MASK_TYPE_ERROR
from .pointer import parse_pointer, resolve
from .policy import Policy
from .spec import DERIVED_PREFIX, ViewSpec


def _canonical_json(obj):
    """跨平台确定性序列化（sort_keys + 无空格），用于快照指纹。"""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _audit(kind, reason, *, view_id=None, event_id=None, column=None, path=None, detail=""):
    """构造一条审计记录；所有字段均来自配置面或稳定枚举。"""
    entry = {"kind": kind, "reason": reason}
    if view_id is not None:
        entry["view_id"] = view_id
    if event_id is not None:
        entry["event_id"] = event_id
    if column is not None:
        entry["column"] = column
    if path is not None:
        entry["path"] = path
    if detail:
        entry["detail"] = detail
    return entry


def apply_mask(value, keep, side, char):
    """定长掩码（独立纯函数，语义对测试直接可验）。

    * 长度 <= keep：全部字符替换为掩码字符
    * left：保留前 keep 个字符；right：保留后 keep 个字符；其余替换
    * keep=0：整体掩码
    仅接受字符串；``None`` 透传（已授权的 null 原样导出，不掩码）。
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ExportError(MASK_TYPE_ERROR, None, "mask 仅支持字符串值")
    if len(value) <= keep:
        return char * len(value)
    if side == "left":
        return value[:keep] + char * (len(value) - keep)
    return char * (len(value) - keep) + value[len(value) - keep:]


# 排序时的类型秩：缺失列 < JSON null < 布尔 < 数字 < 字符串 < 数组 < 对象
_TYPE_RANK = {type(None): 0, bool: 1, int: 2, float: 2, str: 3, list: 4, dict: 5}


def _sort_key(value, missing_sentinel=False):
    """生成可比较的排序载荷；容器按规范 JSON 字符串定序。"""
    if missing_sentinel:
        return (-1, "")
    rank = _TYPE_RANK.get(type(value), 5)
    if isinstance(value, (list, dict)):
        return (rank, _canonical_json(value))
    if value is None:
        return (rank, "")
    if isinstance(value, bool):
        return (rank, str(int(value)))
    return (rank, value)


class _ViewRunner:
    def __init__(self, view, policy, role_name, audit_log):
        self.view = view
        self.policy = policy
        self.role_name = role_name
        self.audit = audit_log

    def run(self, events):
        vid = self.view.spec_id
        rows = []
        rejected = 0
        omitted = 0
        for event in events:
            if not isinstance(event, dict):
                continue
            if event.get("event_type") != self.view.event_type:
                continue  # 非本视图事件类型：静默跳过，不产生审计
            event_id = event.get("event_id")
            payload = event.get("payload", {})
            tenant = event.get("tenant")

            # 事件级门槛（租户/类型），失败则整事件拒绝
            try:
                role = self.policy.check_event(self.role_name, tenant, self.view.event_type)
            except ExportError as exc:
                self.audit.append(
                    _audit("event_rejected", exc.code, view_id=vid, event_id=event_id,
                           detail=exc.detail)
                )
                rejected += 1
                continue

            row, ok, event_omitted = self._evaluate_event(role, event_id, payload, vid)
            omitted += event_omitted
            if ok:
                row_out = {"event_id": event_id, "tenant": tenant,
                           "event_type": self.view.event_type, "values": row}
                rows.append(row_out)
            else:
                rejected += 1

        self._sort_rows(rows)
        return {
            "view_id": vid,
            "spec_version": self.view.version,
            "event_type": self.view.event_type,
            "status": "ok",
            "rows": rows,
            "stats": {
                "events_in_scope": sum(
                    1 for e in events
                    if isinstance(e, dict) and e.get("event_type") == self.view.event_type
                ),
                "rows_exported": len(rows),
                "events_rejected": rejected,
                "optional_columns_omitted": omitted,
            },
        }

    def _evaluate_event(self, role, event_id, payload, vid):
        memo = {}          # 列名 -> 值（仅成功列）
        omitted = 0
        for name in self.view.topo_order:
            col = self.view.columns[name]
            try:
                memo[name] = self._evaluate_column(col, role, payload, memo, vid, event_id)
            except ExportError as exc:
                if col.required:
                    # 必需列不满足 -> 拒绝该事件；审计只含配置面路径/原因
                    self.audit.append(
                        _audit("event_rejected", exc.code, view_id=vid, event_id=event_id,
                               column=name, path=exc.path, detail=exc.detail)
                    )
                    return None, False, omitted
                # 可选列不满足 -> 省略该列
                self.audit.append(
                    _audit("column_omitted", exc.code, view_id=vid, event_id=event_id,
                           column=name, path=exc.path, detail=exc.detail)
                )
                omitted += 1
        return {name: memo[name] for name in self.view.column_order if name in memo}, True, omitted

    def _evaluate_column(self, col, role, payload, memo, vid, event_id):
        # 1) 授权：该列的全部传递原始路径都必须可读
        for pointer_text in self.view.transitive_raw[col.name]:
            segments = parse_pointer(pointer_text)
            self.policy.check_path(
                role, self.view.event_type, segments, pointer_text, payload
            )
        # 2) 计算
        return self._compute(col, payload, memo, vid, event_id)

    def _compute(self, col, payload, memo, vid, event_id):
        source = col.source_raw
        if col.kind == "pointer":
            return self._read_pointer(source["path"], payload)
        if col.kind == "mask":
            value = self._read_pointer(source["path"], payload)
            return apply_mask(value, source["keep"], source.get("side", "left"),
                              source.get("char", "*"))
        # concat：逐源求值，字段引用必须为字符串，字面量原样拼接
        pieces = []
        for ref in source["parts"]:
            if isinstance(ref, dict):
                pieces.append(ref["literal"])
            elif ref.startswith(DERIVED_PREFIX):
                dep = ref[1:]
                if dep not in memo:
                    # 依赖的可选列已被省略：结构性失败（原因仍为配置面信息）
                    raise ExportError(CONCAT_TYPE_ERROR, None,
                                      "concat 依赖的派生列不可用: %r" % dep)
                pieces.append(self._as_string(memo[dep], ref))
            else:
                pieces.append(self._as_string(self._read_pointer(ref, payload), ref))
        return "".join(pieces)

    @staticmethod
    def _as_string(value, ref):
        if not isinstance(value, str):
            # 不输出 value 本身，只记录是哪个**配置源**类型不符
            raise ExportError(CONCAT_TYPE_ERROR, ref if ref.startswith("/") else None,
                              "concat 组成部分不是字符串")
        return value

    @staticmethod
    def _read_pointer(pointer_text, payload):
        segments = parse_pointer(pointer_text)
        try:
            return resolve(payload, segments)
        except ExportError as exc:
            # 统一附上配置面指针原文；不附加任何实际键名/值
            raise ExportError(exc.code, pointer_text, exc.detail) from None

    def _sort_rows(self, rows):
        sort_spec = self.view.sort

        def one_column(row, column, direction):
            values = row["values"]
            if column not in values:
                # 缺失列固定排最后：(1, ...) 大于任何真实值键 (0, ...)
                return (1, 0, "")
            rank, payload = _sort_key(values.get(column))
            if direction == "desc":
                # 同类型秩内载荷反向；类型秩本身保持正向（类型不混合比较）
                if isinstance(payload, (int, float)) and not isinstance(payload, bool):
                    payload = -payload
                elif isinstance(payload, str):
                    payload = _ReversedText(payload)
            return (0, rank, payload)

        def row_key(row):
            parts = [one_column(row, column, direction)
                     for column, direction in sort_spec]
            parts.append(_sort_key(row["event_id"]))  # 确定性兜底
            return tuple(parts)

        rows.sort(key=row_key)


class _ReversedText:
    """字符串反向排序包装：按 Unicode 码点逆序比较。"""

    __slots__ = ("text",)

    def __init__(self, text):
        self.text = text

    def __lt__(self, other):
        if not isinstance(other, _ReversedText):
            return NotImplemented
        return self.text > other.text

    def __eq__(self, other):
        return isinstance(other, _ReversedText) and self.text == other.text


def _validate_job(job):
    if not isinstance(job, dict):
        raise ExportError("SPEC_INVALID_META", None, "导出任务必须为 JSON 对象")
    for field in ("job_id", "role", "policy", "views", "events"):
        if field not in job:
            raise ExportError("SPEC_INVALID_META", None, "任务缺少字段: %s" % field)
    if not isinstance(job["role"], str):
        raise ExportError("SPEC_INVALID_META", None, "role 必须为字符串")
    if not isinstance(job["views"], list) or not job["views"]:
        raise ExportError("SPEC_INVALID_META", None, "views 必须为非空数组")
    if not isinstance(job["events"], list):
        raise ExportError("SPEC_INVALID_META", None, "events 必须为数组")


def run_batch(document):
    """运行一个回放文档：单任务对象或 ``{"jobs": [任务...]}`` 批量形态。

    :returns: 单任务返回结果对象；批量返回 ``{"results": [结果...]}``
    """
    if isinstance(document, dict) and "jobs" in document:
        jobs = document["jobs"]
        if not isinstance(jobs, list) or not jobs:
            raise ExportError("SPEC_INVALID_META", None, "jobs 必须为非空数组")
        return {"results": [run_export(job) for job in jobs]}
    return run_export(document)


def run_export(job):
    """执行一次快照化导出，返回结果字典（不做任何 IO）。

    结果中除 ``rows`` 内的授权值外，只包含稳定枚举、事件 ID 与配置面指针，
    可直接 JSON 序列化落盘。
    """
    _validate_job(job)
    # 深拷贝固定快照：后续即便调用方改了入参对象，导出结果也不受影响
    snapshot = copy.deepcopy(job)
    # 配置面指纹：角色、策略、规格与作业标识；刻意不含事件数据。
    # 成对隐私作业仅事件未授权枝不同，配置面指纹必然相同。
    config_digest = hashlib.sha256(
        _canonical_json({
            "job_id": snapshot["job_id"],
            "role": snapshot["role"],
            "policy": snapshot["policy"],
            "views": snapshot["views"],
        }).encode("utf-8")
    ).hexdigest()
    # 数据面指纹：覆盖固定下来的事件集合，用于快照完整性核对
    events_digest = hashlib.sha256(
        _canonical_json(snapshot["events"]).encode("utf-8")
    ).hexdigest()
    snapshot_digest = hashlib.sha256(
        (config_digest + events_digest).encode("utf-8")
    ).hexdigest()

    audit_log = []
    policy = Policy(snapshot["policy"])
    role_name = snapshot["role"]
    if role_name not in policy.roles:
        audit_log.append(_audit("export_rejected", "ROLE_UNKNOWN",
                                detail="快照绑定的角色不存在"))

    result_views = []
    for view_raw in snapshot["views"]:
        # 规格校验失败 -> 整版拒绝，该视图不产出任何行
        try:
            view = ViewSpec(view_raw)
        except ExportError as exc:
            audit_log.append(_audit("spec_rejected", exc.code,
                                    view_id=view_raw.get("spec_id")
                                    if isinstance(view_raw, dict) else None,
                                    path=exc.path, detail=exc.detail))
            result_views.append({
                "view_id": view_raw.get("spec_id") if isinstance(view_raw, dict) else None,
                "status": "rejected",
                "reason": exc.code,
                "rows": [],
                "stats": {"events_in_scope": 0, "rows_exported": 0,
                          "events_rejected": 0, "optional_columns_omitted": 0},
            })
            continue

        # 角色未知时由 check_event 在逐事件处理中统一记 ROLE_UNKNOWN
        runner = _ViewRunner(view, policy, role_name, audit_log)
        result_views.append(runner.run(snapshot["events"]))

    return {
        "job_id": snapshot["job_id"],
        "snapshot": {
            "role": role_name,
            "policy_id": policy.policy_id,
            "policy_version": policy.version,
            "spec_versions": [
                {"view_id": v.get("view_id"),
                 "spec_version": v.get("spec_version")}
                for v in result_views
            ],
            "event_count": len(snapshot["events"]),
            "sha256": snapshot_digest,
            "config_sha256": config_digest,
            "events_sha256": events_digest,
        },
        "views": result_views,
        "audit": audit_log,
    }
