"""导出引擎测试：掩码/拼接独立期望值、必需与可选列、成对隐私、快照隔离。

所有期望值在测试内以独立判定给出：
* 掩码用测试自带的 ``expected_mask`` 独立函数计算；
* 行值用手工字面量断言；
* 不读取 result 去反推期望。
"""

import copy
import json
import unittest

from solution.errors import (
    CONCAT_TYPE_ERROR,
    MASK_TYPE_ERROR,
    PATH_GLOBAL_BLOCKED,
    PATH_NOT_AUTHORIZED,
    POINTER_MISSING,
    SPEC_COLUMN_NAME_CONFLICT,
    SPEC_DERIVED_CYCLE,
    SPEC_DEP_MISSING,
)
from solution.export import apply_mask, run_export


def expected_mask(value, keep, side, char):
    """测试侧独立判定：用最直白的字符串切片重写一遍掩码规则。"""
    if value is None:
        return None
    n = len(value)
    if n <= keep:
        return char * n
    if side == "left":
        return value[0:keep] + char * (n - keep)
    return char * (n - keep) + value[(n - keep):n]


POLICY = {
    "policy_id": "p", "version": 1,
    "roles": {
        "analyst": {
            "tenants": ["t-a"],
            "event_types": ["e1"],
            "paths": {"e1": ["/id", "/name", "/phone", "/region", "/amount"]},
        },
    },
    "global_blocks": [
        {"event_type": "e1", "path": "/secret"},
    ],
}


def _event(event_id, payload, tenant="t-a", etype="e1"):
    return {"event_id": event_id, "tenant": tenant,
            "event_type": etype, "payload": payload}


def _job(views, events, role="analyst"):
    return {"job_id": "j", "role": role, "policy": POLICY,
            "views": views, "events": events}


def _job_with_policy(policy, views, events, role="analyst"):
    return {"job_id": "j", "role": role, "policy": policy,
            "views": views, "events": events}


def _view(columns, spec_id="v", sort=None):
    doc = {"spec_id": spec_id, "version": 1, "event_type": "e1",
           "columns": columns}
    if sort is not None:
        doc["sort"] = sort
    return doc


def _ptr(name, path, required=True):
    return {"name": name, "required": required,
            "source": {"type": "pointer", "path": path}}


def _mask(name, path, keep, side="left", char="*", required=True):
    return {"name": name, "required": required,
            "source": {"type": "mask", "path": path, "keep": keep,
                       "side": side, "char": char}}


class TestMaskIndependentExpectations(unittest.TestCase):
    def test_mask_table(self):
        # 手工表 + 独立函数双重判定，两路口径一致才通过
        samples = [
            ("1234567890", 4, "left", "*"),
            ("1234567890", 4, "right", "#"),
            ("abc", 5, "left", "*"),     # keep >= 长度：全掩
            ("abc", 0, "left", "*"),     # keep=0：全掩
            ("", 3, "left", "*"),        # 空串
            ("x", 1, "right", "-"),      # 长度 == keep：全掩
        ]
        for value, keep, side, char in samples:
            with self.subTest(value=value, keep=keep, side=side):
                got = apply_mask(value, keep, side, char)
                self.assertEqual(got, expected_mask(value, keep, side, char))

    def test_mask_manual_literals(self):
        # 纯字面量断言，不经过任何辅助函数
        self.assertEqual(apply_mask("1234567890", 4, "left", "*"), "1234******")
        self.assertEqual(apply_mask("1234567890", 4, "right", "#"), "######7890")
        self.assertEqual(apply_mask("abc", 5, "left", "*"), "***")
        self.assertIsNone(apply_mask(None, 2, "left", "*"))  # 授权 null 透传

    def test_mask_rejects_non_string(self):
        for bad in [123, 1.5, ["a"], {"k": 1}, True]:
            with self.subTest(bad=bad):
                with self.assertRaises(Exception) as ctx:
                    apply_mask(bad, 1, "left", "*")
                self.assertEqual(ctx.exception.code, MASK_TYPE_ERROR)


class TestRequiredAndOptional(unittest.TestCase):
    def setUp(self):
        self.view = _view([
            _ptr("id", "/id"),
            _ptr("amount", "/amount"),                       # 必需但会缺失
            _ptr("region", "/region", required=False),       # 可选
            _ptr("secret_probe", "/secret", required=False),  # 可选但被封锁
        ])

    def test_optional_missing_or_blocked_is_omitted_required_missing_rejects(self):
        events = [_event("e-ok", {"id": "i1", "amount": 10, "region": "CN"}),
                  _event("e-bad", {"id": "i2", "region": "CN"})]  # 缺 amount
        result = run_export(_job([self.view], events))
        view = result["views"][0]
        self.assertEqual(view["stats"]["events_rejected"], 1)
        self.assertEqual(view["stats"]["rows_exported"], 1)
        row = view["rows"][0]
        self.assertEqual(row["event_id"], "e-ok")
        self.assertEqual(row["values"],
                         {"id": "i1", "amount": 10, "region": "CN"})
        reasons = [(a["event_id"], a["kind"], a["reason"], a.get("path"))
                   for a in result["audit"]]
        self.assertIn(("e-bad", "event_rejected", POINTER_MISSING, "/amount"), reasons)
        # 被封锁的可选列：省略且只记录配置路径
        self.assertIn(("e-ok", "column_omitted", PATH_GLOBAL_BLOCKED, "/secret"), reasons)

    def test_authorized_null_exports_as_null(self):
        view = _view([_ptr("id", "/id"), _ptr("phone", "/phone")])
        events = [_event("e-null", {"id": "i", "phone": None})]
        result = run_export(_job([view], events))
        # 关键区分：授权路径上的 null 是真实值，必须导出 None 而不是省略
        self.assertEqual(result["views"][0]["rows"][0]["values"],
                         {"id": "i", "phone": None})

    def test_missing_key_distinct_from_null(self):
        view = _view([_ptr("id", "/id"), _ptr("phone", "/phone")])
        events = [_event("e-missing", {"id": "i"})]  # 无 phone 键
        result = run_export(_job([view], events))
        self.assertEqual(result["views"][0]["stats"]["events_rejected"], 1)
        self.assertEqual(result["audit"][0]["reason"], POINTER_MISSING)
        self.assertEqual(result["audit"][0]["path"], "/phone")


class TestNoLaundering(unittest.TestCase):
    """角色不能通过 concat、间接派生拿到未授权字段。"""

    def test_concat_with_unauthorized_source_rejected(self):
        view = _view([
            _ptr("id", "/id"),
            {"name": "mix", "required": True, "source": {
                "type": "concat", "parts": ["/id", {"literal": "::"}, "/secret"]}},
        ])
        result = run_export(_job([view], [_event("e", {"id": "i", "secret": "S"})]))
        self.assertEqual(result["views"][0]["stats"]["rows_exported"], 0)
        self.assertEqual(result["audit"][0]["reason"], PATH_GLOBAL_BLOCKED)
        self.assertEqual(result["audit"][0]["path"], "/secret")

    def test_indirect_derived_reference_rejected(self):
        view = _view([
            _ptr("id", "/id"),
            _ptr("holder", "/secret"),  # 必需列本身即被封锁
            {"name": "laundered", "required": True, "source": {
                "type": "concat", "parts": [{"literal": "x="}, "$holder"]}},
        ])
        result = run_export(_job([view], [_event("e", {"id": "i", "secret": "S"})]))
        self.assertEqual(result["views"][0]["stats"]["rows_exported"], 0)
        # 第一现场是 holder 列的封锁，派生列没有机会执行
        self.assertEqual(result["audit"][0]["column"], "holder")
        self.assertEqual(result["audit"][0]["reason"], PATH_GLOBAL_BLOCKED)

    def test_concat_type_error_when_component_not_string(self):
        # /amount 是数字，concat 不做隐式 str() —— 固定形态、类型失败
        view = _view([
            _ptr("id", "/id"),
            {"name": "bad", "required": True, "source": {
                "type": "concat", "parts": ["/id", "/amount"]}},
        ])
        result = run_export(_job([view], [_event("e", {"id": "i", "amount": 7})]))
        self.assertEqual(result["views"][0]["stats"]["events_rejected"], 1)
        self.assertEqual(result["audit"][0]["reason"], CONCAT_TYPE_ERROR)

    def test_unauthorized_path_even_without_block(self):
        # 无封锁策略；角色只持有 /id，拼接 /region（未授权）必须被拒
        policy = copy.deepcopy(POLICY)
        policy["global_blocks"] = []
        policy["roles"]["analyst"]["paths"]["e1"] = ["/id"]
        view = _view([
            _ptr("id", "/id"),
            {"name": "mix", "required": True, "source": {
                "type": "concat", "parts": ["/id", "/region"]}},
        ])
        result = run_export(_job_with_policy(policy, [view],
                                             [_event("e", {"id": "i", "region": "CN"})]))
        self.assertEqual(result["views"][0]["stats"]["events_rejected"], 1)
        self.assertEqual(result["audit"][0]["reason"], PATH_NOT_AUTHORIZED)


class TestPrivacyPair(unittest.TestCase):
    """成对输入：只改未授权枝的键名与值，导出结果与审计必须完全一致。"""

    def test_pair_outputs_identical_and_contain_no_secret(self):
        view = _view([
            _ptr("id", "/id"),
            _mask("name_masked", "/name", 1, "left", "*"),
            _ptr("secret_probe", "/secret", required=False),
        ])
        payload_a = {"id": "O1", "name": "alice",
                     "secret": "ALPHA-SECRET", "nested": {"k": [1, 2]}}
        payload_b = {"id": "O1", "name": "alice",
                     "secret_renamed": "BETA-DIFFERENT-999",
                     "other_branch": [None, True, 3.14]}
        ra = run_export(_job([view], [_event("ev", payload_a)]))
        rb = run_export(_job([view], [_event("ev", payload_b)]))
        # 配置面指纹相同：差异不来自配置
        self.assertEqual(ra["snapshot"]["config_sha256"],
                         rb["snapshot"]["config_sha256"])
        # 归一化（去掉作业标识与数据面指纹）后逐字节一致
        def normalized(result):
            clone = copy.deepcopy(result)
            clone.pop("job_id", None)
            snap = clone["snapshot"]
            snap.pop("sha256", None)
            snap.pop("events_sha256", None)
            return json.dumps(clone, sort_keys=True, ensure_ascii=False)

        self.assertEqual(normalized(ra), normalized(rb))
        # 任何未授权值/键名都不得出现在序列化输出里
        serialized = json.dumps(ra, ensure_ascii=False)
        for forbidden in ["ALPHA-SECRET", "BETA-DIFFERENT-999",
                          "secret_renamed", "other_branch", "nested"]:
            self.assertNotIn(forbidden, serialized)
        # 正常授权值与独立计算的掩码值仍在
        self.assertEqual(ra["views"][0]["rows"][0]["values"]["name_masked"],
                         expected_mask("alice", 1, "left", "*"))


class TestSnapshotIsolation(unittest.TestCase):
    def test_mutating_input_after_run_does_not_change_result(self):
        view = _view([_ptr("id", "/id"), _mask("m", "/name", 2, "right", "#")])
        events = [_event("ev", {"id": "i", "name": "carol"})]
        job = _job([view], events)
        before = run_export(job)
        # 调用后篡改输入对象
        events[0]["payload"]["name"] = "CHANGED"
        events[0]["payload"]["secret"] = "new-secret"
        after = run_export(job)
        # 同一份 job 再次运行当然反映新对象；这里验证的是首次结果未被别名污染
        self.assertEqual(before["views"][0]["rows"][0]["values"]["m"],
                         expected_mask("carol", 2, "right", "#"))
        self.assertNotEqual(
            before["views"][0]["rows"][0]["values"]["m"],
            after["views"][0]["rows"][0]["values"]["m"],
        )

    def test_snapshot_digest_stable_and_changes_with_input(self):
        view = _view([_ptr("id", "/id")])
        job1 = _job([view], [_event("ev", {"id": "i"})])
        r1 = run_export(job1)
        r1_again = run_export(copy.deepcopy(job1))
        # 同输入重放：三个指纹都稳定
        self.assertEqual(r1["snapshot"]["sha256"], r1_again["snapshot"]["sha256"])
        self.assertEqual(r1["snapshot"]["config_sha256"],
                         r1_again["snapshot"]["config_sha256"])
        # 只改事件数据：配置面指纹不变，数据面与总指纹变化
        job_diff_events = _job([view], [_event("ev", {"id": "DIFFERENT"})])
        rd = run_export(job_diff_events)
        self.assertEqual(r1["snapshot"]["config_sha256"], rd["snapshot"]["config_sha256"])
        self.assertNotEqual(r1["snapshot"]["events_sha256"], rd["snapshot"]["events_sha256"])
        self.assertNotEqual(r1["snapshot"]["sha256"], rd["snapshot"]["sha256"])
        # 只改配置（换策略版本）：配置面与总指纹变化
        policy2 = copy.deepcopy(POLICY)
        policy2["policy_id"] = "p-changed"
        job_diff_cfg = _job_with_policy(policy2, [view], [_event("ev", {"id": "i"})])
        rc = run_export(job_diff_cfg)
        self.assertNotEqual(r1["snapshot"]["config_sha256"], rc["snapshot"]["config_sha256"])
        self.assertEqual(r1["snapshot"]["events_sha256"], rc["snapshot"]["events_sha256"])


class TestSorting(unittest.TestCase):
    def test_sort_by_declared_column_with_event_id_tiebreak(self):
        view = _view([_ptr("id", "/id"), _ptr("amount", "/amount")],
                     sort=[{"column": "amount", "direction": "desc"}])
        events = [_event("e3", {"id": "c", "amount": 10}),
                  _event("e1", {"id": "a", "amount": 30}),
                  _event("e2", {"id": "b", "amount": 30})]
        result = run_export(_job([view], events))
        order = [r["event_id"] for r in result["views"][0]["rows"]]
        # 30 的两个按 event_id 升序兜底，10 最后
        self.assertEqual(order, ["e1", "e2", "e3"])

    def test_missing_optional_sort_column_sorts_last(self):
        view = _view([_ptr("id", "/id"), _ptr("region", "/region", required=False)],
                     sort=[{"column": "region", "direction": "asc"}])
        events = [_event("e-miss", {"id": "m"}),
                  _event("e-b", {"id": "b", "region": "CN-BJ"}),
                  _event("e-a", {"id": "a", "region": "CN-AH"})]
        result = run_export(_job([view], events))
        order = [r["event_id"] for r in result["views"][0]["rows"]]
        self.assertEqual(order, ["e-a", "e-b", "e-miss"])


class TestUnknownRoleAndRootPointer(unittest.TestCase):
    def test_unknown_role_rejects_all_events_with_job_audit(self):
        view = _view([_ptr("id", "/id")])
        result = run_export(_job([view], [_event("e", {"id": "i"})], role="ghost"))
        # 作业级一条 ROLE_UNKNOWN，且每个在 scope 的事件再各记一条事件级拒绝
        codes = [a["reason"] for a in result["audit"]]
        self.assertIn("ROLE_UNKNOWN", codes)
        self.assertEqual(result["views"][0]["stats"]["rows_exported"], 0)
        self.assertEqual(result["views"][0]["stats"]["events_rejected"], 1)

    def test_root_pointer_reads_whole_payload_when_authorized(self):
        # 空指针 "" 表示整个 payload；角色精确授权 "" 且无封锁时可整体读取
        policy = copy.deepcopy(POLICY)
        policy["global_blocks"] = []
        policy["roles"]["analyst"]["paths"]["e1"] = [""]
        view = _view([_ptr("whole", "")])
        payload = {"id": "i", "name": "n"}
        result = run_export(_job_with_policy(policy, [view], [_event("e", payload)]))
        self.assertEqual(result["views"][0]["rows"][0]["values"]["whole"], payload)


class TestSpecLevelRejectionInEngine(unittest.TestCase):
    def test_three_whole_version_rejections(self):
        good = _view([_ptr("id", "/id")], spec_id="good")
        dup = _view([_ptr("a", "/id"), _ptr("a", "/name")], spec_id="dup")
        cycle = _view([
            {"name": "a", "source": {"type": "concat", "parts": ["$b"]}},
            {"name": "b", "source": {"type": "concat", "parts": ["$a"]}},
        ], spec_id="cycle")
        missing = _view([
            {"name": "a", "source": {"type": "concat", "parts": ["$ghost"]}},
        ], spec_id="missing")
        result = run_export(_job([good, dup, cycle, missing],
                                 [_event("e", {"id": "i", "name": "n"})]))
        statuses = {v["view_id"]: (v["status"], v.get("reason")) for v in result["views"]}
        self.assertEqual(statuses["good"][0], "ok")
        self.assertEqual(statuses["dup"], ("rejected", SPEC_COLUMN_NAME_CONFLICT))
        self.assertEqual(statuses["cycle"], ("rejected", SPEC_DERIVED_CYCLE))
        self.assertEqual(statuses["missing"], ("rejected", SPEC_DEP_MISSING))
        # 被拒视图零产出
        for v in result["views"]:
            if v["status"] == "rejected":
                self.assertEqual(v["rows"], [])


if __name__ == "__main__":
    unittest.main()
