from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from fwagent.dynamic.models import DynamicEvidence, DynamicHypothesis, EmulationState


class DynamicWorkspace:
    def __init__(self, workspace_root: str | Path, task_id: str):
        self.workspace_root = Path(workspace_root).resolve()
        self.task_id = task_id
        self.task_dir = self.workspace_root / task_id
        self.dynamic_dir = self.task_dir / "dynamic"
        self.logs_dir = self.dynamic_dir / "logs"
        self.network_dir = self.dynamic_dir / "network"
        self.evidence_dir = self.dynamic_dir / "evidence"
        self.input_dir = self.dynamic_dir / "input"
        self.validation_dir = self.dynamic_dir / "validation"
        self.prioritization_dir = self.dynamic_dir / "prioritization"
        self.correlation_dir = self.task_dir / "correlation"
        self.surface_dir = self.task_dir / "surface"
        self.taint_dir = self.task_dir / "taint"
        self.hypotheses_dir = self.task_dir / "hypotheses"
        self.investigation_dir = self.task_dir / "investigation"
        self.simulation_dir = self.task_dir / "simulation"
        for directory in (
            self.logs_dir,
            self.network_dir,
            self.evidence_dir,
            self.input_dir,
            self.validation_dir,
            self.prioritization_dir,
            self.correlation_dir,
            self.surface_dir,
            self.taint_dir,
            self.hypotheses_dir,
            self.investigation_dir,
            self.simulation_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)

    def load_report(self) -> dict[str, Any]:
        path = self.task_dir / "reports" / "analysis.json"
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def resolve_firmware(self) -> Path | None:
        report = self.load_report()
        candidate = report.get("firmware", {}).get("path") or report.get("firmware", {}).get("filename")
        if not candidate:
            return None
        # 跨平台：Windows 反斜杠路径在 POSIX Path 下 .name 不切分，
        # 统一规范化后再取文件名（否则容器内回退路径拼接错误）
        normalized = str(candidate).replace("\\", "/")
        name = normalized.rsplit("/", 1)[-1]
        path = Path(normalized)
        if not path.exists():
            alt = self.task_dir / "input" / name
            if alt.exists():
                return alt
            return None
        return path

    def prepare_firmware(self) -> dict[str, Any]:
        source = self.resolve_firmware()
        if not source:
            return {"success": False, "errors": ["firmware path not found"]}
        target = self.input_dir / source.name
        if not target.exists():
            shutil.copy2(source, target)
        return {"success": True, "firmware": str(source), "prepared": str(target)}

    def load_state(self) -> EmulationState | None:
        path = self.dynamic_dir / "state.json"
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return EmulationState(**data)

    def save_state(self, state: EmulationState) -> None:
        path = self.dynamic_dir / "state.json"
        path.write_text(json.dumps(state.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def load_evidence(self) -> list[DynamicEvidence]:
        path = self.evidence_dir / "evidence.json"
        if not path.exists():
            return []
        return [DynamicEvidence(**item) for item in json.loads(path.read_text(encoding="utf-8"))]

    def save_evidence(self, evidence: list[DynamicEvidence]) -> None:
        path = self.evidence_dir / "evidence.json"
        path.write_text(
            json.dumps([item.to_dict() for item in evidence], indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def load_hypotheses(self) -> list[DynamicHypothesis]:
        path = self.dynamic_dir / "hypotheses.json"
        if not path.exists():
            return []
        return [DynamicHypothesis(**item) for item in json.loads(path.read_text(encoding="utf-8"))]

    def save_hypotheses(self, hypotheses: list[DynamicHypothesis]) -> None:
        path = self.dynamic_dir / "hypotheses.json"
        path.write_text(
            json.dumps([item.to_dict() for item in hypotheses], indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def save_tool_trace(self, trace: list[dict[str, Any]]) -> None:
        path = self.dynamic_dir / "tool_trace.json"
        path.write_text(json.dumps(trace, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def validation_run_dir(self, validation_id: str) -> Path:
        path = self.validation_dir / validation_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def save_validation_artifact(self, validation_id: str, name: str, payload: Any) -> Path:
        path = self.validation_run_dir(validation_id) / name
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def load_validation_artifact(self, validation_id: str, name: str) -> Any | None:
        path = self.validation_run_dir(validation_id) / name
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def save_prioritization_artifact(self, name: str, payload: Any) -> Path:
        path = self.prioritization_dir / name
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def load_prioritization_artifact(self, name: str) -> Any | None:
        path = self.prioritization_dir / name
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def save_correlation_artifact(self, name: str, payload: Any) -> Path:
        path = self.correlation_dir / name
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def load_correlation_artifact(self, name: str) -> Any | None:
        path = self.correlation_dir / name
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def save_surface_artifact(self, name: str, payload: Any) -> Path:
        path = self.surface_dir / name
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def load_surface_artifact(self, name: str) -> Any | None:
        path = self.surface_dir / name
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def save_taint_artifact(self, name: str, payload: Any) -> Path:
        path = self.taint_dir / name
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def load_taint_artifact(self, name: str) -> Any | None:
        path = self.taint_dir / name
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def save_hypothesis_artifact(self, name: str, payload: Any) -> Path:
        path = self.hypotheses_dir / name
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def load_hypothesis_artifact(self, name: str) -> Any | None:
        path = self.hypotheses_dir / name
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def save_investigation_artifact(self, name: str, payload: Any) -> Path:
        path = self.investigation_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def load_investigation_artifact(self, name: str) -> Any | None:
        path = self.investigation_dir / name
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def save_simulation_artifact(self, name: str, payload: Any) -> Path:
        path = self.simulation_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def load_simulation_artifact(self, name: str) -> Any | None:
        path = self.simulation_dir / name
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def write_log(self, name: str, content: str) -> Path:
        path = self.logs_dir / name
        with path.open("a", encoding="utf-8") as handle:
            handle.write(content)
            if not content.endswith("\n"):
                handle.write("\n")
        return path
