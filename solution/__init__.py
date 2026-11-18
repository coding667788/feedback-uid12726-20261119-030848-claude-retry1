"""离线事件导出 —— 授权证明与来源隔离。

模块组成::

    errors   错误码与统一异常
    pointer  RFC 6901 JSON Pointer 解析与取值
    policy   角色授权 / 全局封锁判定
    spec     版本化导出规格校验与派生列分析
    export   快照化导出引擎
    __main__ 命令行入口
"""

from .export import run_batch, run_export

__all__ = ["run_export", "run_batch"]
