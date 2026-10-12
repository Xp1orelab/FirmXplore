from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fwagent.dynamic.agent import DynamicValidationAgent
from fwagent.dynamic.api import DynamicToolAPI
from fwagent.dynamic.backend import (
    DockerQemuBackend,
    FirmAEBackend,
    QemuUserServiceBackend,
    _classify_boot,
    _read_text,
    create_backend,
)
from fwagent.dynamic.capabilities import DynamicCapabilities, detect_capabilities
from fwagent.dynamic.compat.image_builder import UserspaceImageBuilder
from fwagent.dynamic.config import DynamicConfig
from fwagent.dynamic.docker import DockerController, DockerUnavailableError
from fwagent.dynamic.models import DynamicEvidence
from fwagent.dynamic.network import UserModeNetworkBackend
from fwagent.dynamic.winpaths import host_and_container_paths, host_to_container
from fwagent.models import CommandResult


class StubRunner:
    def __init__(self):
        self.runs = []

    def run(self, command, **kwargs):
        self.runs.append(command)
        if command and command[0] == "mke2fs" and len(command) >= 5:
            Path(command[-2]).touch()
        return CommandResult(command=command, exit_code=0, stdout="stub", stderr="", duration=0.1)


class Round31Tests(unittest.TestCase):
    def test_userspace_image_builder_builds_image(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "rootfs"
            root.mkdir()
            (root / "etc").mkdir()
            (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\n", encoding="utf-8")
            output = Path(tmp) / "images" / "rootfs.ext4"
            runner = StubRunner()

            result = UserspaceImageBuilder(runner).build(root, output, size_mb=64)

            self.assertTrue(result.success)
            self.assertEqual(result.builder, "userspace")
            self.assertTrue(result.output_path.exists())

    def test_user_mode_network_creates_forwarded_target(self) -> None:
        network = UserModeNetworkBackend(forwarded_ports=(80,))
        prepared = network.prepare([80])
        target = network.get_target(80)

        self.assertEqual(prepared["backend"], "qemu-user-network")
        self.assertEqual(target.host_port, 18080)
        self.assertEqual(target.transport, "qemu-user-network")
        # guest_ip 现在显式指向固件出厂 LAN IP（默认回退 QEMU user 网络地址）
        self.assertIn("hostfwd=tcp:127.0.0.1:18080-10.0.2.15:80", " ".join(network.qemu_args()))

    def test_capability_detection_and_backend_fallback(self) -> None:
        compatible = DynamicCapabilities(
            docker=True,
            qemu_arm=True,
            qemu_mips=False,
            loop_devices=False,
            tun=False,
            kvm=False,
            userspace_image_builder=True,
            qemu_user_network=True,
            native_firmae=False,
            compatible_backend=True,
        )
        native = DynamicCapabilities(
            docker=True,
            qemu_arm=True,
            qemu_mips=True,
            loop_devices=True,
            tun=True,
            kvm=False,
            userspace_image_builder=True,
            qemu_user_network=True,
            native_firmae=True,
            compatible_backend=False,
        )
        with tempfile.TemporaryDirectory() as tmp, patch("fwagent.dynamic.backend.detect_capabilities", return_value=compatible):
            self.assertIsInstance(create_backend(DynamicConfig(backend="firmae"), Path(tmp)), DockerQemuBackend)
        with tempfile.TemporaryDirectory() as tmp, patch("fwagent.dynamic.backend.detect_capabilities", return_value=native):
            self.assertIsInstance(create_backend(DynamicConfig(backend="firmae"), Path(tmp)), FirmAEBackend)
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsInstance(create_backend(DynamicConfig(backend="service-qemu"), Path(tmp)), QemuUserServiceBackend)

    def test_windows_path_conversion(self) -> None:
        self.assertEqual(host_to_container(r"C:\Users\Me\firmware.bin"), "/work/c/Users/Me/firmware.bin")
        converted = host_to_container(r"D:\Git-Projects\FirmXplore\workspace\a b\固件.bin")
        self.assertTrue(converted.startswith("/work/d/"))
        mapped = host_to_container(r"D:\Git-Projects\FirmXplore\workspace\a", [("D:\\Git-Projects\\FirmXplore", "/work")])
        self.assertEqual(mapped, "/work/workspace/a")
        info = host_and_container_paths("C:\\firmware.bin")
        self.assertIn("host_path", info)
        self.assertIn("container_path", info)

    def test_docker_unavailable_raises_clear_error(self) -> None:
        class FailingRunner:
            def run(self, command, **kwargs):
                return CommandResult(command=command, exit_code=1, stdout="", stderr="denied", duration=0.1)

        controller = DockerController(runner=FailingRunner())
        with self.assertRaises(DockerUnavailableError) as caught:
            controller.ensure_available()
        self.assertIn("Docker Desktop is not available.", str(caught.exception))

    def test_validation_blocked_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            task = root / "task"
            (task / "reports").mkdir(parents=True)
            firmware = task / "firmware.bin"
            firmware.write_bytes(b"\x1f\x8b")
            (task / "reports" / "analysis.json").write_text(
                json.dumps({"firmware": {"path": str(firmware)}, "extraction": {"rootfs": None}}),
                encoding="utf-8",
            )
            api = DynamicToolAPI(root, "task", backend=StubFailingBackend())
            agent = DynamicValidationAgent(root, "task", config=DynamicConfig(backend="stub"))
            agent.api = api

            agent.api.execute("dynamic.boot_firmware", {})
            agent._finalize_hypothesis()

            hypothesis = agent.api.hypotheses[0]
            self.assertEqual(hypothesis.status, "validation_blocked")
            self.assertEqual(hypothesis.dynamic_status, "validation_blocked")
            self.assertTrue(any(item.type == "validation_blocked" for item in agent.api.evidence))

    def test_validation_inconclusive_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            task = root / "task"
            (task / "reports").mkdir(parents=True)
            firmware = task / "firmware.bin"
            firmware.write_bytes(b"\x1f\x8b")
            (task / "reports" / "analysis.json").write_text(
                json.dumps({"firmware": {"path": str(firmware)}, "extraction": {"rootfs": None}}),
                encoding="utf-8",
            )
            api = DynamicToolAPI(root, "task", backend=StubFailingBackend())
            api._create_evidence(
                {
                    "type": "port_closed",
                    "observation": "probe returned closed",
                    "source_tool": "tcp_probe",
                }
            )
            agent = DynamicValidationAgent(root, "task", config=DynamicConfig(backend="stub"))
            agent.api = api

            agent._finalize_hypothesis()

            self.assertEqual(agent.api.hypotheses[0].status, "validation_inconclusive")

    def test_service_backend_executes_rootfs_shell(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            task = root / "task"
            rootfs = task / "rootfs"
            (rootfs / "bin").mkdir(parents=True)
            (rootfs / "bin" / "sh").write_bytes(b"\x7fELF")
            (rootfs / "bin" / "busybox").write_bytes(b"\x7fELF")
            (task / "reports").mkdir(parents=True)
            firmware = task / "firmware.bin"
            firmware.write_bytes(b"\x1f\x8b")
            (task / "reports" / "analysis.json").write_text(
                json.dumps({"firmware": {"path": str(firmware)}, "extraction": {"rootfs": str(rootfs)}}),
                encoding="utf-8",
            )
            runner = StubRunner()
            backend = QemuUserServiceBackend(task, runner=runner)

            result = backend.boot(firmware, timeout=5)

            self.assertTrue(result["success"])
            self.assertEqual(runner.runs[0][3], str(rootfs / "bin" / "busybox"))
            self.assertEqual(runner.runs[0][4:], ["uname", "-m"])

    def test_console_file_is_read_for_boot_classification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            console = Path(tmp) / "console.log"
            console.write_text(
                "EXT4-fs (vda): Couldn't mount because of unsupported optional features (2000)\n"
                "Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(254,0)\n",
                encoding="utf-8",
            )

            content = _read_text(console)
            diagnosis, errors = _classify_boot(content, None, False)

            self.assertIn("unsupported optional features", content)
            self.assertEqual(diagnosis, "rootfs_mount_failure")
            self.assertEqual(errors, ["Root filesystem mount failed"])


class StubFailingBackend:
    name = "stub"

    def prepare(self, firmware_path):
        return {"success": True}

    def boot(self, firmware_path, *, timeout=300):
        return {"success": False, "errors": ["boot failed"], "diagnosis": "timeout"}

    def status(self):
        return {"status": "failed"}

    def stop(self):
        return {"success": True}

    def logs(self, limit=200):
        return []

    def check_environment(self):
        return {"success": True}


if __name__ == "__main__":
    unittest.main()
