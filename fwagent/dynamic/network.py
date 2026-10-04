from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ForwardedPort:
    guest_port: int
    host: str
    host_port: int
    transport: str


class EmulationNetworkBackend:
    name = "base"

    def __init__(self, machine: str = "virt") -> None:
        # 网卡设备随 QEMU 机器类型变化：virt（ARM）有 virtio-mmio 总线，
        # malta（MIPS）走 PCI 的 pcnet32（Firmadyne/FirmAE 内核内置驱动）。
        self.machine = machine

    def _nic_device(self) -> str:
        return "virtio-net-device" if self.machine.startswith("virt") else "e1000"

    def prepare(self, guest_ports: list[int] | None = None) -> dict[str, Any]:
        raise NotImplementedError

    def get_target(self, guest_port: int) -> ForwardedPort | None:
        raise NotImplementedError

    def cleanup(self) -> dict[str, Any]:
        return {"success": True}

    def qemu_args(self) -> list[str]:
        return []


class UserModeNetworkBackend(EmulationNetworkBackend):
    name = "qemu-user-network"

    def __init__(self, forwarded_ports: tuple[int, ...] = (80,), machine: str = "virt"):
        super().__init__(machine=machine)
        self.forwarded_ports = tuple(forwarded_ports)
        self.ports: dict[int, ForwardedPort] = {}

    def prepare(self, guest_ports: list[int] | None = None) -> dict[str, Any]:
        ports = tuple(dict.fromkeys(guest_ports or list(self.forwarded_ports)))
        self.ports = {
            guest_port: ForwardedPort(
                guest_port=guest_port,
                host="127.0.0.1",
                host_port=18000 + guest_port,
                transport="qemu-user-network",
            )
            for guest_port in ports
        }
        return {
            "backend": self.name,
            "forwarded": {
                str(guest_port): {
                    "guest_service": guest_port,
                    "transport": item.transport,
                    "forwarded_endpoint": f"{item.host}:{item.host_port}",
                }
                for guest_port, item in self.ports.items()
            },
        }

    def get_target(self, guest_port: int) -> ForwardedPort | None:
        return self.ports.get(guest_port)

    def qemu_args(self) -> list[str]:
        args = ["-device", f"{self._nic_device()},netdev=net0"]
        hostfwd = []
        for guest_port, item in self.ports.items():
            hostfwd.append(f"hostfwd=tcp:{item.host}:{item.host_port}-:{guest_port}")
        args.extend(["-netdev", "user,id=net0," + ",".join(hostfwd)])
        return args


class TapNetworkBackend(EmulationNetworkBackend):
    name = "tap"

    def prepare(self, guest_ports: list[int] | None = None) -> dict[str, Any]:
        return {
            "success": False,
            "errors": ["TAP networking requires /dev/net/tun; unavailable in this environment"],
        }

    def get_target(self, guest_port: int) -> ForwardedPort | None:
        return None

    def qemu_args(self) -> list[str]:
        return ["-device", f"{self._nic_device()},netdev=net0", "-netdev", "tap,id=net0"]
