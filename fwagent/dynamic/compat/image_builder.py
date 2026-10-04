from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fwagent.runtime.command import CommandRunner


@dataclass
class ImageBuildResult:
    success: bool
    output_path: Path | None
    filesystem_type: str
    image_size_mb: int
    builder: str
    duration: float
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "output_path": str(self.output_path) if self.output_path else None,
            "filesystem_type": self.filesystem_type,
            "image_size_mb": self.image_size_mb,
            "builder": self.builder,
            "duration": self.duration,
            "errors": self.errors,
            "metadata": self.metadata,
        }


class FirmwareImageBuilder:
    name = "base"

    def build(
        self,
        rootfs: str | Path,
        output_path: str | Path,
        *,
        size_mb: int = 256,
    ) -> ImageBuildResult:
        raise NotImplementedError


class LoopImageBuilder(FirmwareImageBuilder):
    name = "loop"

    def __init__(self, runner: CommandRunner | None = None):
        self.runner = runner or CommandRunner(Path("workspace") / "dynamic" / "logs")

    def build(self, rootfs, output_path, *, size_mb=256) -> ImageBuildResult:
        return ImageBuildResult(
            success=False,
            output_path=Path(output_path),
            filesystem_type="ext4",
            image_size_mb=size_mb,
            builder=self.name,
            duration=0.0,
            errors=["loop device workflow requires /dev/loop*; use UserspaceImageBuilder on Docker Desktop"],
        )


class UserspaceImageBuilder(FirmwareImageBuilder):
    name = "userspace"

    def __init__(self, runner: CommandRunner | None = None):
        self.runner = runner or CommandRunner(Path("workspace") / "dynamic" / "logs")

    def build(
        self,
        rootfs: str | Path,
        output_path: str | Path,
        *,
        size_mb: int = 256,
    ) -> ImageBuildResult:
        start = time.monotonic()
        root = Path(rootfs)
        output = Path(output_path)
        if not root.is_dir():
            return ImageBuildResult(
                success=False,
                output_path=output,
                filesystem_type="ext4",
                image_size_mb=size_mb,
                builder=self.name,
                duration=round(time.monotonic() - start, 3),
                errors=[f"rootfs directory not found: {root}"],
            )
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists():
            output.unlink()
        command = [
            "mke2fs",
            "-t",
            # FirmAE 的 2.6 内核没有 ext4 驱动（内核日志 do_mount type:ext3），
            # ext2（无 extents/journal）在 2.6 与 4.1 内核上均可挂载
            "ext2",
            "-F",
            "-d",
            str(root),
            str(output),
            f"{size_mb}M",
        ]
        result = self.runner.run(command, timeout=300)
        success = result.exit_code == 0 and output.exists()
        return ImageBuildResult(
            success=success,
            output_path=output,
            filesystem_type="ext2",
            image_size_mb=size_mb,
            builder=self.name,
            duration=round(time.monotonic() - start, 3),
            errors=[] if success else [(result.stderr or result.stdout or "mke2fs failed")[:2000]],
            metadata={
                "command": command,
                "rootfs": str(root),
                "exit_code": result.exit_code,
            },
        )
