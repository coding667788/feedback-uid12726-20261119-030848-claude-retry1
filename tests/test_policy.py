"""授权判定测试：全局封锁优先、解码段匹配、数组整体读取、数字字典键。

策略与事件在本文件内独立构造；每条期望对应题目一条明确规则，
不使用被测实现生成期望值。
"""

import unittest

from solution.errors import (
    EVENT_TYPE_DENIED,
    ExportError,
    PATH_ARRAY_BLOCKED,
    PATH_GLOBAL_BLOCKED,
    PATH_NOT_AUTHORIZED,
    ROLE_UNKNOWN,
    TENANT_DENIED,
)
from solution.policy import Policy
from solution.pointer import parse_pointer

POLICY_DOC = {
    "policy_id": "p", "version": 1,
    "roles": {
        "r1": {
            "tenants": ["t-a", "t-b"],
            "event_types": ["e1"],
            "paths": {"e1": ["/a", "/a/b", "/arr", "/obj/0", "/n"]},
        },
        "r2": {
            # 无 tenants 字段：不限制租户；但只授权 e2
            "event_types": ["e2"],
            "paths": {"e2": ["/x"]},
        },
    },
    "global_blocks": [
        {"event_type": "e1", "path": "/a/secret"},       # 字典枝精确/后代封锁
        {"event_type": "e1", "path": "/arr/0"},          # 数组子路径封锁
        {"event_type": "e1", "path": "/enc/key"},        # 两段嵌套枝封锁
    ],
}


def _event(payload):
    return {"payload": payload, "tenant": "t-a", "event_type": "e1"}


class TestEventGate(unittest.TestCase):
    def setUp(self):
        self.policy = Policy(POLICY_DOC)

    def test_unknown_role(self):
        with self.assertRaises(ExportError) as ctx:
            self.policy.check_event("ghost", "t-a", "e1")
        self.assertEqual(ctx.exception.code, ROLE_UNKNOWN)

    def test_tenant_denied(self):
        with self.assertRaises(ExportError) as ctx:
            self.policy.check_event("r1", "t-other", "e1")
        self.assertEqual(ctx.exception.code, TENANT_DENIED)

    def test_event_type_denied(self):
        with self.assertRaises(ExportError) as ctx:
            self.policy.check_event("r1", "t-a", "e9")
        self.assertEqual(ctx.exception.code, EVENT_TYPE_DENIED)

    def test_role_without_tenant_list_covers_any_tenant(self):
        role = self.policy.check_event("r2", "any-tenant", "e2")
        self.assertIn("e2", role["event_types"])


class TestPathAuthorization(unittest.TestCase):
    def setUp(self):
        self.policy = Policy(POLICY_DOC)
        self.role = self.policy.roles["r1"]

    def _allow(self, path, payload):
        # 不抛异常即授权通过
        self.policy.check_path(
            self.role, "e1", parse_pointer(path), path, payload
        )

    def _deny(self, path, payload, expected_code):
        with self.assertRaises(ExportError) as ctx:
            self.policy.check_path(
                self.role, "e1", parse_pointer(path), path, payload
            )
        self.assertEqual(ctx.exception.code, expected_code)
        # 异常只回写配置面指针原文
        self.assertEqual(ctx.exception.path, path)

    def test_exact_grant_allowed(self):
        self._allow("/a/b", {"a": {"b": 1}})
        self._allow("/n", {"n": None})  # 已授权 null

    def test_grant_is_exact_no_prefix_inheritance(self):
        # 角色有 /a/b，但没有 /a/c：精确匹配模型下拒绝
        self._deny("/a/c", {"a": {"c": 1}}, PATH_NOT_AUTHORIZED)
        # 有 /a 也不自动拥有 /a/other
        role2 = {**self.role, "paths": {"e1": frozenset([parse_pointer("/a")])}}
        with self.assertRaises(ExportError) as ctx:
            self.policy.check_path(role2, "e1", parse_pointer("/a/other"),
                                   "/a/other", {"a": {"other": 1}})
        self.assertEqual(ctx.exception.code, PATH_NOT_AUTHORIZED)

    def test_global_block_beats_role_grant(self):
        # 即使角色显式持有 /a/secret，封锁优先
        role = {**self.role,
                "paths": {"e1": self.role["paths"]["e1"] | frozenset(
                    [parse_pointer("/a/secret")])}}
        with self.assertRaises(ExportError) as ctx:
            self.policy.check_path(role, "e1", parse_pointer("/a/secret"),
                                   "/a/secret", {"a": {"secret": "v"}})
        self.assertEqual(ctx.exception.code, PATH_GLOBAL_BLOCKED)

    def test_block_on_descendant_makes_container_unreadable(self):
        # /a 已授权，但 /a/secret 被封锁 -> 读 /a 容器同样拒绝
        self._deny("/a", {"a": {"secret": "v", "b": 1}}, PATH_GLOBAL_BLOCKED)

    def test_block_matches_decoded_segments(self):
        # 封锁 /enc/key 解码为两段 ("enc","key")，作用于真实嵌套字典；
        # 即使角色显式授权同一路径，封锁仍优先
        role = {**self.role,
                "paths": {"e1": frozenset([parse_pointer("/enc/key")])}}
        payload = {"enc": {"key": "locked"}}
        with self.assertRaises(ExportError) as ctx:
            self.policy.check_path(role, "e1", parse_pointer("/enc/key"),
                                   "/enc/key", payload)
        self.assertEqual(ctx.exception.code, PATH_GLOBAL_BLOCKED)

        # 含 "/" 的单段键：指针 /a~1b 解码为 ("a/b",)，与两段路径严格区分，
        # 封锁不会误伤这个不同枝；角色授权后可正常读取
        role2 = {**self.role,
                 "paths": {"e1": frozenset([parse_pointer("/a~1b")])}}
        self.policy.check_path(role2, "e1", parse_pointer("/a~1b"),
                               "/a~1b", {"a/b": "different-branch"})

    def test_block_encoding_ambiguity_cannot_bypass(self):
        # 真实键含 "/"：指针写作 /a~1b，解码为单段 ("a/b",)。
        # 封锁与角色授权都按解码段存储，换任何等价编码都绕不过封锁。
        policy = Policy({
            "policy_id": "p", "version": 1,
            "roles": {"r": {"event_types": ["e1"], "paths": {"e1": ["/a~1b"]}}},
            "global_blocks": [{"event_type": "e1", "path": "/a~1b"}],
        })
        with self.assertRaises(ExportError) as ctx:
            policy.check_path(policy.roles["r"], "e1",
                              parse_pointer("/a~1b"), "/a~1b", {"a/b": "locked"})
        self.assertEqual(ctx.exception.code, PATH_GLOBAL_BLOCKED)

    def test_array_whole_read_allowed_when_clean(self):
        # /arr 整体授权且封锁子路径不影响“干净数组”之外的路径；
        # 但本策略中 /arr/0 被封锁 -> 含封锁后代，整体读被拒
        self._deny("/arr", {"arr": [1, 2]}, PATH_ARRAY_BLOCKED)

    def test_array_whole_read_allowed_without_block(self):
        # 换一个没有数组封锁的策略验证整体读取可以通过
        policy = Policy({
            "policy_id": "p2", "version": 1,
            "roles": {"r": {"event_types": ["e1"],
                            "paths": {"e1": ["/arr"]}}},
            "global_blocks": [],
        })
        role = policy.roles["r"]
        policy.check_path(role, "e1", parse_pointer("/arr"), "/arr",
                          {"arr": [1, 2, 3]})  # 不抛即通过

    def test_entering_array_always_blocked(self):
        # 即使没有任何封锁，数组子路径也禁止
        policy = Policy({
            "policy_id": "p3", "version": 1,
            "roles": {"r": {"event_types": ["e1"],
                            "paths": {"e1": ["/arr/0", "/arr"]}}},
            "global_blocks": [],
        })
        role = policy.roles["r"]
        with self.assertRaises(ExportError) as ctx:
            policy.check_path(role, "e1", parse_pointer("/arr/0"), "/arr/0",
                              {"arr": [1]})
        self.assertEqual(ctx.exception.code, PATH_ARRAY_BLOCKED)

    def test_numeric_dict_key_is_not_array_index(self):
        # 容器是 dict：段 "0" 按字典键处理；已授权 /obj/0 则通过
        self._allow("/obj/0", {"obj": {"0": "dict-key-zero"}})
        # 未授权的数字字典键 -> PATH_NOT_AUTHORIZED（而不是数组错误）
        self._deny("/obj/1", {"obj": {"1": "x"}}, PATH_NOT_AUTHORIZED)
        # 同一指针在 list 容器上则是数组深入错误
        self._deny("/obj/0", {"obj": [10, 20]}, PATH_ARRAY_BLOCKED)

    def test_block_decision_does_not_require_key_existence(self):
        # 被封锁路径即便在事件里缺失，判定仍是封锁（不可探测存在性）
        self._deny("/a/secret", {"a": {}}, PATH_GLOBAL_BLOCKED)

    def test_block_event_type_scoping(self):
        # 封锁只对 e1 生效；换成 e2 时不应用该封锁
        role = {**self.role, "event_types": frozenset(["e2"]),
                "paths": {"e2": frozenset([parse_pointer("/a/secret")])}}
        # e2 下无封锁且精确授权 -> 通过
        self.policy.check_path(role, "e2", parse_pointer("/a/secret"),
                               "/a/secret", {"a": {"secret": "v"}})


if __name__ == "__main__":
    unittest.main()
