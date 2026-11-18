"""CLI 端到端与 cases.json 回放测试。

* 通过 ``python -m solution`` 子进程走完整命令行路径；
* 成对作业结果一致性在回放数据上再验一次；
* 对结果全文做秘密特征扫描，验证来源隔离。
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CASES_PATH = os.path.join(REPO_ROOT, "cases.json")

# cases.json 中只存在于未授权枝的秘密特征，任何结果文件都不得包含
FORBIDDEN_TOKENS = [
    "SHOULD-NEVER-LEAK",
    "ALPHA-SECRET",
    "DIFFERENT-secret-999",
    "tok-secret",
    "secret_renamed",
    "extra_unauthorized_branch",
]


class TestCliReplay(unittest.TestCase):
    def test_cli_runs_cases_and_writes_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "result.json")
            proc = subprocess.run(
                [sys.executable, "-m", "solution",
                 "--input", CASES_PATH, "--output", out],
                cwd=REPO_ROOT, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            with open(out, encoding="utf-8") as fh:
                result = json.load(fh)

        self.assertIn("results", result)
        job_ids = [r["job_id"] for r in result["results"]]
        self.assertEqual(job_ids, ["job-main", "job-pair-a", "job-pair-b"])

    def test_pair_jobs_byte_identical_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "result.json")
            subprocess.run(
                [sys.executable, "-m", "solution",
                 "--input", CASES_PATH, "--output", out],
                cwd=REPO_ROOT, capture_output=True, text=True, check=True,
            )
            with open(out, encoding="utf-8") as fh:
                result = json.load(fh)
        pair_a, pair_b = result["results"][1], result["results"][2]
        # 两个成对作业的 job_id 不同（配置面输入的一部分），因此配置面指纹本就不同；
        # 真正要证明的是：仅未授权枝不同不会改变任何可见结果。
        # 归一化（去除作业标识与全部指纹）后逐字节一致
        def normalized(doc):
            clone = json.loads(json.dumps(doc))
            clone.pop("job_id", None)
            snap = clone["snapshot"]
            for key in ("sha256", "events_sha256", "config_sha256"):
                snap.pop(key, None)
            return json.dumps(clone, sort_keys=True, ensure_ascii=False)

        self.assertEqual(normalized(pair_a), normalized(pair_b))
        # 成对作业各导出 1 行，掩码值按独立规则核对
        row = pair_a["views"][0]["rows"][0]["values"]
        self.assertEqual(row["order_id"], "O-PAIR")
        self.assertEqual(row["name_masked"], "P********")  # keep=1,left,"Pair User"(9)
        self.assertNotIn("secret_probe", row)              # 被封锁可选列省略

    def test_no_unauthorized_content_anywhere(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "result.json")
            subprocess.run(
                [sys.executable, "-m", "solution",
                 "--input", CASES_PATH, "--output", out],
                cwd=REPO_ROOT, capture_output=True, text=True, check=True,
            )
            with open(out, encoding="utf-8") as fh:
                text = fh.read()
        for token in FORBIDDEN_TOKENS:
            self.assertNotIn(token, text, "未授权内容泄露到导出结果: %s" % token)

    def test_main_job_expected_view_outcomes(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "result.json")
            subprocess.run(
                [sys.executable, "-m", "solution",
                 "--input", CASES_PATH, "--output", out],
                cwd=REPO_ROOT, capture_output=True, text=True, check=True,
            )
            with open(out, encoding="utf-8") as fh:
                result = json.load(fh)
        main = result["results"][0]
        by_id = {v["view_id"]: v for v in main["views"]}

        # 主订单视图：5 个在 scope，1 个因必需 amount 缺失被拒，4 行导出
        order = by_id["order-view"]
        self.assertEqual(order["stats"]["events_in_scope"], 5)
        self.assertEqual(order["stats"]["rows_exported"], 4)
        self.assertEqual(order["stats"]["events_rejected"], 1)
        ids = [r["event_id"] for r in order["rows"]]
        self.assertEqual(ids, ["ev-order-01", "ev-order-02", "ev-order-03", "ev-order-05"])

        # ev-order-03：授权 null 导出 None；缺失 region 使可选 contact 省略
        row03 = next(r for r in order["rows"] if r["event_id"] == "ev-order-03")
        self.assertNotIn("contact", row03["values"])

        # 三个拒绝类视图：零行 + 各自原因码
        self.assertEqual(by_id["order-array-required-view"]["stats"]["events_rejected"], 5)
        self.assertEqual(by_id["order-concat-forbidden-view"]["stats"]["events_rejected"], 5)
        self.assertEqual(by_id["order-indirect-derived-view"]["stats"]["events_rejected"], 5)

        # 整版拒绝的坏规格
        for bad, reason in [
            ("bad-duplicate", "SPEC_COLUMN_NAME_CONFLICT"),
            ("bad-cycle", "SPEC_DERIVED_CYCLE"),
            ("bad-missing-dep", "SPEC_DEP_MISSING"),
        ]:
            self.assertEqual(by_id[bad]["status"], "rejected")
            self.assertEqual(by_id[bad]["reason"], reason)

        # 审计里的 path 全部来自配置面：必须是 cases 中出现过的指针
        configured = _collect_configured_paths(json.load(open(CASES_PATH, encoding="utf-8")))
        for entry in main["audit"]:
            if "path" in entry:
                self.assertIn(entry["path"], configured,
                              "审计出现非配置面路径: %r" % entry["path"])

    def test_single_job_input_form_supported(self):
        # 题目规定的主用法：输入直接是单个任务对象
        doc = json.load(open(CASES_PATH, encoding="utf-8"))
        single = doc["jobs"][1]
        with tempfile.TemporaryDirectory() as tmp:
            inp = os.path.join(tmp, "one.json")
            out = os.path.join(tmp, "out.json")
            with open(inp, "w", encoding="utf-8") as fh:
                json.dump(single, fh)
            proc = subprocess.run(
                [sys.executable, "-m", "solution",
                 "--input", inp, "--output", out],
                cwd=REPO_ROOT, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            with open(out, encoding="utf-8") as fh:
                result = json.load(fh)
        self.assertNotIn("results", result)  # 单任务直接返回结果对象
        self.assertEqual(result["job_id"], "job-pair-a")
        self.assertIn("snapshot", result)


def _collect_configured_paths(cases):
    """收集 cases 内所有规格/策略配置面出现过的指针字符串。"""
    pointers = set()

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("path",) and isinstance(value, str):
                    pointers.add(value)
                if key == "parts" and isinstance(value, list):
                    for part in value:
                        if isinstance(part, str) and part.startswith("/"):
                            pointers.add(part)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(cases)
    return pointers


if __name__ == "__main__":
    unittest.main()
