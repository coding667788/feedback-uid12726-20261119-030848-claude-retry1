"""命令行入口::

    python -m solution --input cases.json --output result.json

纯标准库、离线运行；输入文件按 UTF-8 读取，输出按 UTF-8（无 BOM）写入。
"""

import argparse
import json
import sys

from .errors import ExportError
from .export import run_batch


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m solution",
        description="离线事件导出（授权证明与来源隔离）",
    )
    parser.add_argument("--input", required=True, help="导出任务 JSON 文件路径")
    parser.add_argument("--output", required=True, help="导出结果 JSON 写入路径")
    args = parser.parse_args(argv)

    try:
        with open(args.input, "r", encoding="utf-8") as fh:
            job = json.load(fh)
    except FileNotFoundError:
        print("输入文件不存在: %s" % args.input, file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print("输入文件不是合法 JSON: %s" % exc, file=sys.stderr)
        return 1

    try:
        result = run_batch(job)
    except ExportError as exc:
        # 任务级结构错误（无法构造快照）：输出最小错误信封，不落任何事件内容
        envelope = {
            "job_id": job.get("job_id") if isinstance(job, dict) else None,
            "status": "job_rejected",
            "reason": exc.code,
            "path": exc.path,
            "detail": exc.detail,
        }
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(envelope, fh, ensure_ascii=False, indent=2, sort_keys=True)
        print("导出任务被拒绝: %s" % exc.code, file=sys.stderr)
        return 1

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")

    if "results" in result:
        total_rows = sum(
            len(v.get("rows", []))
            for r in result["results"]
            for v in r["views"]
        )
        print("批量导出完成: %d 个任务, 共 %d 行"
              % (len(result["results"]), total_rows))
    else:
        total_rows = sum(len(v.get("rows", [])) for v in result["views"])
        print("导出完成: %d 个视图, %d 行, %d 条审计记录"
              % (len(result["views"]), total_rows, len(result["audit"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
