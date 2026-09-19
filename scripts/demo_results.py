"""Reproducible demo artifacts and measurements. Active traffic targets only our loopback listener.

Run from the repository with its development environment. Timings describe this machine,
not a promise for every USB drive, network or cloud account.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import platform
import socket
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from PySide6.QtWidgets import QApplication
from discovr.native import MainWindow, write_report
from discovr.network import NetworkDiscovery


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--screenshots-only", action="store_true", help="Refresh visuals without replacing measured evidence")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication(["Discovr demo capture"])
    window = MainWindow(demo=True)
    window.show()
    app.processEvents()
    window.grab().save(str(args.output / "demo.png"))
    for fmt in ("json", "csv", "html"):
        write_report(args.output / f"demo.{fmt}", window.model.assets, fmt)
    window.filters["Environment"].setCurrentIndex(window.filters["Environment"].findData("Example production"))
    app.processEvents()
    window.grab().save(str(args.output / "filtered.png"))
    window._allow_close = True
    window.close()
    if args.screenshots_only:
        return
    measured = {"platform": platform.platform(), "python": platform.python_version(),
                "note": "Local SSD/development measurements. Sample inventory is fictional. Network test is real loopback only."}
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        port = listener.getsockname()[1]
        first = []
        started = time.perf_counter()
        assets, _, elapsed = NetworkDiscovery("127.0.0.1", ports=str(port)).run(
            on_asset=lambda row: first.append(time.perf_counter() - started) if not first else None)
        measured["loopback"] = {"first_result_ms": round(first[0] * 1000, 2),
                                "complete_ms": round(elapsed * 1000, 2), "assets": len(assets),
                                "open_port": port, "port_detected": assets[0]["Ports"] == str(port)}
        # Keep local resolver names out of public artifacts; measured counts/ports
        # are sufficient to reproduce the test without publishing host metadata.
    window = MainWindow()
    window.show()
    # Reserved IPv6 documentation addresses keep these benchmark records non-operational.
    base = int(ipaddress.IPv6Address("2001:db8::"))
    rows = [{"IP": str(ipaddress.IPv6Address(base + i)), "Hostname": f"sample-node-{i:05}",
             "OS": "Linux", "Source": "Import", "Demo": True} for i in range(10000)]
    started = time.perf_counter()
    window.session.merge(rows)
    window.refresh()
    app.processEvents()
    measured["inventory_10000"] = {"load_ms": round((time.perf_counter() - started) * 1000, 2)}
    window.search.setText("sample-node-09999")
    started = time.perf_counter()
    window.apply_filters()
    app.processEvents()
    measured["inventory_10000"].update(filter_ms=round((time.perf_counter() - started) * 1000, 2),
                                      matches=window.proxy.rowCount())
    window._allow_close = True
    window.close()
    (args.output / "measurements.json").write_text(json.dumps(measured, indent=2), encoding="utf-8")
    print(json.dumps(measured, indent=2))


if __name__ == "__main__":
    main()
