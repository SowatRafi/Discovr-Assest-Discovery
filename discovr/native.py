"""Native Qt Widgets desktop. Workers own discovery; only the GUI thread touches widgets.

The desktop calls Session directly. Normal startup opens no listener or browser.
An optional loopback API can be enabled explicitly; it contains no website.
"""
from datetime import datetime
import ipaddress
import json
import logging
import os
from pathlib import Path
import sys
import tempfile
import threading
import time

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, QSortFilterProxyModel, Qt, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QIcon, QKeySequence
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog,
    QFormLayout, QGridLayout, QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow,
    QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QScrollArea, QSpinBox, QSplitter,
    QStackedWidget, QTableView, QTableWidget, QTableWidgetItem, QTabWidget,
    QToolBar, QVBoxLayout, QWidget,
)

from discovr import __version__
from discovr.core import CORE_FIELDS, _cell_text, to_csv, to_html, to_json
from discovr.session import BadRequest, Session, _ActivityHandler
from discovr.core import is_blank

SOURCES = [("Network", "network"), ("Neighbour cache", "passive"), ("Active Directory", "ad"),
           ("Amazon Web Services", "aws"), ("Microsoft Azure", "azure"), ("Google Cloud", "gcp")]
FORMATS = {"json": to_json, "csv": to_csv, "html": to_html}
LABELS = {"Tag": "Device type", "AgentCapable": "Agent capable", "OS": "OS hint"}
RISK_COLOURS = {"Critical": "#ad172a", "High": "#a9480d", "Medium": "#806000", "Low": "#20704f"}


def plain_label(text):
    label = QLabel(text)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    return label


def write_report(path, assets, fmt):
    """Replace only a complete report; disk-full/removal must not destroy an older export."""
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="", dir=path.parent,
                                         prefix=f".{path.name}.", suffix=".tmp", delete=False) as output:
            temporary = Path(output.name)
            output.write(FORMATS[fmt](assets))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class InventoryModel(QAbstractTableModel):
    """One record per row; no widget per cell, so large inventories remain usable."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.assets = []
        self.keys = []
        self.search_text = []
        self.ip_keys = []
        self.columns = list(CORE_FIELDS)

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.assets)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.columns)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        key = self.columns[index.column()]
        asset = self.assets[index.row()]
        value = asset.get(key)
        if role == Qt.ItemDataRole.ToolTipRole:
            if key == "OS":
                return asset.get("OSEvidence") or "No OS evidence in this record. Select the device and choose Identify selected to check its services."
            if key == "Ports":
                return asset.get("PortStatus") or ("Ports were not checked by this source. Use Identify selected for an active TCP check." if is_blank(value) else "Recorded ports; double-click for source and scan details.")
            if key == "Tag":
                return asset.get("DeviceEvidence") or "Device type is estimated from OS, hostname and services. Use Identify selected to gather more evidence."
        if role == Qt.ItemDataRole.DisplayRole:
            if key == "OS" and is_blank(value):
                return "Not identified"
            if key == "Tag":
                return "Not identified" if value == "[Unknown]" else str(value or "Not identified").strip("[]")
            if key == "Ports" and is_blank(value):
                if asset.get("DiscoveryStatus") == "Scanning":
                    return "Checking…"
                if asset.get("DiscoveryStatus") == "Stopped early":
                    return "Incomplete check"
                if asset.get("PortsChecked"):
                    return "No open ports found" if asset.get("TCPResponses") else "No TCP response"
                return "Not checked"
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            return _cell_text(value) if value is not None else "Unknown"
        if role == Qt.ItemDataRole.ForegroundRole and key == "Risk":
            # Keep triage colours legible in the operating system's light and dark themes.
            dark = QApplication.palette().base().color().lightness() < 128
            colours = {"Critical": "#ff8996", "High": "#ffb37b", "Medium": "#f2d37b", "Low": "#89d8b3"} if dark else RISK_COLOURS
            return QColor(colours.get(value, "#aaaaaa" if dark else "#555555"))
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole:
            return LABELS.get(self.columns[section], self.columns[section]) if orientation == Qt.Orientation.Horizontal else section + 1
        return None

    def replace(self, assets, keys=None):
        keys = keys if keys is not None else list(range(len(assets)))
        old_count = len(self.assets)
        if keys[:old_count] != self.keys or len(keys) < old_count:
            self.beginResetModel()
            self.assets, self.keys = assets, keys
            self.search_text = [self.searchable(a) for a in assets]
            self.ip_keys = [self.ip_key(a) for a in assets]
            self.endResetModel()
            return
        # Keep persistent indexes, selection and scroll position while scans stream.
        # Cache search strings once per changed asset, rather than on every keystroke.
        for row in range(old_count):
            if assets[row] != self.assets[row]:
                self.assets[row] = assets[row]
                self.search_text[row] = self.searchable(assets[row])
                self.ip_keys[row] = self.ip_key(assets[row])
                self.dataChanged.emit(self.index(row, 0), self.index(row, len(self.columns) - 1))
        if len(assets) > old_count:
            self.beginInsertRows(QModelIndex(), old_count, len(assets) - 1)
            self.assets.extend(assets[old_count:])
            self.keys.extend(keys[old_count:])
            self.search_text.extend(self.searchable(a) for a in assets[old_count:])
            self.ip_keys.extend(self.ip_key(a) for a in assets[old_count:])
            self.endInsertRows()

    @staticmethod
    def searchable(asset):
        return " ".join(_cell_text(v) for v in asset.values()).casefold()

    @staticmethod
    def ip_key(asset):
        value = str(asset.get("IP") or "")
        try:
            address = ipaddress.ip_address(value)
            return (0, address.version, int(address))
        except ValueError:
            return (1, 0, value.casefold())


class InventoryFilter(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.query = ""
        self.subnet = None
        self.criteria = {}
        self.setSortCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

    def filterAcceptsRow(self, row, parent):
        asset = self.sourceModel().assets[row]
        if self.subnet:
            try:
                if ipaddress.ip_address(str(asset.get("IP"))) not in self.subnet:
                    return False
            except ValueError:
                return False
        elif self.query and self.query not in self.sourceModel().search_text[row]:
            return False
        for key, value in self.criteria.items():
            if value is None:
                continue
            observed = asset.get(key)
            if key == "Source":
                if value not in [v.strip() for v in str(observed or "").replace(";", ",").split(",")]:
                    return False
            elif observed != value:
                return False
        return True

    def lessThan(self, left, right):
        column = self.sourceModel().columns[left.column()]
        a, b = (self.sourceModel().assets[index.row()].get(column) for index in (left, right))
        if column == "IP":
            keys = self.sourceModel().ip_keys
            return keys[left.row()] < keys[right.row()]
        if column == "Risk":
            order = ["Critical", "High", "Medium", "Low"]
            return (order.index(a) if a in order else 4) < (order.index(b) if b in order else 4)
        return super().lessThan(left, right)


class PreparationSignals(QObject):
    finished = Signal(str, object, object)
    imported = Signal(str, object, object)
    network_detected = Signal(object, object, int, bool)


class MainWindow(QMainWindow):
    def __init__(self, session=None, demo=False):
        super().__init__()
        self.session = session or Session()
        self.demo = demo
        self.demo_windows = []
        self.integration = None
        self._preparing = False
        self._importing = False
        self._detecting_network = False
        self._target_revision = 0
        self.preparation = PreparationSignals(self)
        self.preparation.finished.connect(self.scan_prepared)
        self.preparation.imported.connect(self.import_finished)
        self.preparation.network_detected.connect(self.network_detected)
        self.version = -1
        self.saved_version = 0
        self.activity_seq = 0
        self.fields = {}
        self.secret_fields = []
        self._allow_close = False
        self._jobs_signature = None
        location = Path.home() / "Documents"
        if getattr(sys, "frozen", False):
            location = Path(sys.executable).resolve().parent
            # Mac reports belong beside the .app, never inside its signed resources.
            if sys.platform == "darwin":
                location = next((p.parent for p in location.parents if p.suffix == ".app"), location)
        self.last_folder = str(location)
        self.setWindowIcon(QIcon(str(Path(__file__).with_name("assets") / "logo.svg")))
        self.setWindowTitle(f"Discovr {__version__} — Asset discovery[*]")
        available = QApplication.primaryScreen().availableGeometry()
        self.resize(min(1280, available.width() - 40), min(820, available.height() - 60))
        self.setMinimumSize(920, 620)
        font = self.font()
        font.setPointSizeF(max(10, font.pointSizeF()))
        self.setFont(font)
        self._build_actions()
        splitter = QSplitter(self)
        splitter.addWidget(self._build_forms())
        splitter.addWidget(self._build_inventory())
        splitter.setSizes([300, 980])
        splitter.setCollapsible(0, False)
        splitter.setCollapsible(1, False)
        self.setCentralWidget(splitter)
        self.statusBar().showMessage("Ready. Choose a source and start discovery.")
        self.log_handler = _ActivityHandler(self.session)
        self.app_logger = logging.getLogger("discovr")
        self.previous_log_level = self.app_logger.level
        if not demo:
            self.app_logger.setLevel(logging.INFO)
            self.app_logger.addHandler(self.log_handler)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(250)
        self.refresh()
        if demo:
            from discovr.demo import demo_assets
            self.session.merge(demo_assets())
            self.refresh()
            self.saved_version = self.version
            self.setWindowModified(False)
            self.setWindowTitle("Discovr — DEMO · Sample inventory")
            self.start_button.setEnabled(False)
            self.statusBar().showMessage("DEMO · Fictional assets. Discovery is disabled; search, filters and exports work.")
        else:
            # Let the window paint first; local interface reads belong off the GUI thread.
            QTimer.singleShot(0, lambda: self.detect_subnet(initial=True))

    def _action(self, title, callback, shortcut=None):
        action = QAction(title, self)
        action.triggered.connect(callback)
        if shortcut:
            action.setShortcut(shortcut)
        return action

    def _build_actions(self):
        file_menu = self.menuBar().addMenu("&File")
        toolbar = QToolBar("Inventory", self)
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        for title, callback, shortcut in (
            ("Import report…", self.import_dialog, QKeySequence.StandardKey.Open),
            ("Save inventory…", self.save_inventory, QKeySequence.StandardKey.Save),
            ("Export view…", self.export_dialog, "Ctrl+E"),
        ):
            action = self._action(title, callback, shortcut)
            if self.demo and title == "Import report…":
                action.setEnabled(False)
            file_menu.addAction(action)
            toolbar.addAction(action)
        file_menu.addSeparator()
        clear = self._action("Clear results…", self.clear_inventory)
        clear.setEnabled(not self.demo)
        file_menu.addAction(clear)
        file_menu.addAction(self._action("Quit", self.close, QKeySequence.StandardKey.Quit))
        view_menu = self.menuBar().addMenu("&View")
        view_menu.addAction(self._action("Find asset", lambda: self.search.setFocus(), QKeySequence.StandardKey.Find))
        view_menu.addAction(self._action("Reset filters", self.reset_filters))
        tools_menu = self.menuBar().addMenu("&Tools")
        tools_menu.addAction(self._action("Local API integration…", self.show_integration))
        help_menu = self.menuBar().addMenu("&Help")
        help_menu.addAction(self._action("Using Discovr", self.show_help, QKeySequence.StandardKey.HelpContents))
        help_menu.addAction(self._action("Explore sample inventory", self.show_demo))
        help_menu.addAction(self._action("Third-party licences", self.show_licences))
        help_menu.addAction(self._action("About Discovr", self.about))

    def _field(self, layout, kind, key, label, placeholder="", secret=False, browse=False, value=""):
        edit = QLineEdit()
        edit.setObjectName(f"{kind}.{key}")
        edit.setPlaceholderText(placeholder)
        edit.setText(value)
        edit.setAccessibleName(label)
        if secret:
            edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.secret_fields.append(edit)
        self.fields[kind][key] = edit
        if browse:
            row = QWidget()
            box = QHBoxLayout(row)
            box.setContentsMargins(0, 0, 0, 0)
            box.addWidget(edit)
            button = QPushButton("Browse…")
            button.clicked.connect(lambda: self.browse_file(edit))
            box.addWidget(button)
            layout.addRow(label, row)
        else:
            layout.addRow(label, edit)
        return edit

    def _build_forms(self):
        if self.demo:
            return self._build_demo_guide()
        container = QWidget()
        container.setMinimumWidth(270)
        layout = QVBoxLayout(container)
        layout.setSpacing(12)
        heading = plain_label("New discovery")
        font = heading.font()
        font.setPointSize(font.pointSize() + 4)
        font.setBold(True)
        heading.setFont(font)
        layout.addWidget(heading)
        self.source = QComboBox()
        self.source.setAccessibleName("Discovery source")
        for title, kind in SOURCES:
            self.source.addItem(title, kind)
        layout.addWidget(self.source)
        self.forms = QStackedWidget()
        for title, kind in SOURCES:
            self.fields[kind] = {}
            page = QWidget()
            form = QFormLayout(page)
            form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
            form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
            form.setContentsMargins(0, 8, 0, 8)
            f = lambda key, label, **kwargs: self._field(form, kind, key, label, **kwargs)
            if kind == "network":
                self.local_connection = QComboBox()
                self.local_connection.setAccessibleName("This computer's local IPv4 connection")
                self.local_connection.setToolTip("Local IPv4 addresses on this computer, not its public internet address. Choose a connection to use its subnet.")
                self.local_connection.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
                self.local_connection.setMinimumContentsLength(16)
                self.local_connection.addItem("Detecting local IP…")
                self.local_connection.setEnabled(False)
                self.local_connection.currentIndexChanged.connect(self.local_connection_selected)
                form.addRow("This computer · local IPv4", self.local_connection)
                self.local_network_status = plain_label("Reading this computer's connections…")
                form.addRow(self.local_network_status)
                target = f("target", "Target range", placeholder="192.168.1.0/24 or a host IP")
                target.textChanged.connect(self.target_changed)
                self.detect_button = QPushButton("Use local subnet")
                self.detect_button.clicked.connect(self.detect_subnet)
                form.addRow(self.detect_button)
                depth = QComboBox()
                depth.addItem("Standard · more device details", "standard")
                depth.addItem("Quick · common services", "quick")
                depth.setAccessibleName("Discovery detail")
                self.fields[kind]["depth"] = depth
                form.addRow("Discovery detail", depth)
                form.addRow(plain_label("Results appear as devices respond. Quick checks 10 common ports and skips extra fingerprinting."))
                advanced = QWidget()
                options = QFormLayout(advanced)
                options.setContentsMargins(0, 0, 0, 0)
                options.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
                self._field(options, kind, "ports", "TCP ports (optional)", placeholder="e.g. 22,80,443 or 8000-8010")
                intensity = QComboBox()
                for value in ("gentle", "normal", "aggressive"):
                    intensity.addItem(value.title(), value)
                intensity.setCurrentIndex(1)
                self.fields[kind]["intensity"] = intensity
                intensity.setAccessibleName("Scan intensity")
                options.addRow("Scan intensity", intensity)
                options.addRow(plain_label("Gentle reduces network load. Custom ports replace the built-in list."))
                more = QPushButton("More scan options")
                self.advanced_button = more
                self.advanced_panel = advanced
                more.setCheckable(True)
                more.toggled.connect(advanced.setVisible)
                form.addRow(more)
                form.addRow(advanced)
                advanced.hide()
            elif kind == "passive":
                duration = QSpinBox()
                duration.setRange(10, 3600)
                duration.setValue(120)
                duration.setSuffix(" seconds")
                self.fields[kind]["duration"] = duration
                form.addRow("Observe for", duration)
                form.addRow(plain_label("Reads this computer’s neighbour cache without sending packets. Cached devices may be stale; devices absent from the cache will not appear."))
            elif kind == "ad":
                f("domain", "Domain", placeholder="corp.example")
                f("username", "Username", placeholder="user@corp.example")
                f("password", "Password", secret=True)
                f("dc", "Domain controller (optional)", placeholder="DNS host or IP")
                tls = QCheckBox("Use LDAPS (port 636)")
                self.fields[kind]["ldaps"] = tls
                form.addRow(tls)
                f("caFile", "CA certificate (optional)", browse=True)
                form.addRow(plain_label("Uses verified TLS when available, otherwise NTLM. Choose your domain CA to verify an internal certificate."))
            elif kind == "aws":
                f("region", "Region", value="all", placeholder="all or us-east-1")
                f("accessKey", "Access key ID", secret=True)
                f("secretKey", "Secret access key", secret=True)
                f("sessionToken", "Session token (optional)", secret=True)
                f("profile", "Existing profile (optional)")
                form.addRow(plain_label("Enter runtime credentials, or use an existing profile/environment. No AWS CLI is needed for access-key credentials."))
            elif kind == "azure":
                f("tenantId", "Tenant ID")
                f("clientId", "Application / client ID")
                f("clientSecret", "Client secret", secret=True)
                f("subscription", "Subscription ID (optional)")
                form.addRow(plain_label("Use an application with Reader access, or existing environment credentials. Leave subscription empty to enumerate accessible subscriptions."))
            else:
                f("project", "Project ID (optional)")
                f("zone", "Zone (optional)", placeholder="All zones")
                f("credentialsFile", "Service-account JSON key", browse=True)
                form.addRow(plain_label("Choose a service-account key, or use existing application-default credentials. Project defaults to the key’s project."))
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QScrollArea.Shape.NoFrame)
            scroll.setWidget(page)
            self.forms.addWidget(scroll)
        self.source.currentIndexChanged.connect(self.forms.setCurrentIndex)
        self.source.currentIndexChanged.connect(lambda: self.form_error.clear())
        layout.addWidget(self.forms, 1)
        self.environment = QLineEdit()
        self.environment.setPlaceholderText("e.g. Client A / Production")
        self.environment.setMaxLength(80)
        self.environment.setAccessibleName("Environment label (optional)")
        layout.addWidget(plain_label("Environment label (optional)"))
        layout.addWidget(self.environment)
        self.form_error = plain_label("")
        layout.addWidget(self.form_error)
        self.start_button = QPushButton("Start discovery")
        self.start_button.setMinimumHeight(42)
        self.start_button.clicked.connect(self.start_scan)
        layout.addWidget(self.start_button)
        layout.addWidget(plain_label("Credentials stay in memory and are cleared from the form when a scan starts."))
        return container

    def _build_demo_guide(self):
        container = QWidget()
        container.setMinimumWidth(250)
        layout = QVBoxLayout(container)
        layout.setSpacing(16)
        heading = plain_label("Explore Discovr")
        font = heading.font()
        font.setPointSize(font.pointSize() + 4)
        font.setBold(True)
        heading.setFont(font)
        layout.addWidget(heading)
        layout.addWidget(plain_label("10 fictional assets show an office network, directory computers and cloud servers. Your real inventory stays in its own window."))
        for title, callback in (
            ("Office devices · 6 assets", lambda: self.demo_filter("192.0.2.0/24")),
            ("Production · 2 cloud servers", lambda: self.demo_filter("", "Example production")),
            ("Show all sample assets", self.reset_filters),
        ):
            button = QPushButton(title)
            button.setMinimumHeight(36)
            button.clicked.connect(callback)
            layout.addWidget(button)
        layout.addWidget(plain_label("Try it\n\n1. Choose an example above.\n\n2. Select an asset and press Enter to see its evidence.\n\n3. Use Export view to save the visible rows. Every sample row is marked Demo."))
        layout.addStretch()
        self.start_button = QPushButton("Discovery disabled in demo")
        self.start_button.setEnabled(False)
        layout.addWidget(self.start_button)
        close = QPushButton("Close sample inventory")
        close.clicked.connect(self.close)
        layout.addWidget(close)
        return container

    def demo_filter(self, query, environment=None):
        self.reset_filters()
        self.search.setText(query)
        if environment:
            self.filters["Environment"].setCurrentIndex(self.filters["Environment"].findData(environment))
        self.apply_filters()

    def _build_inventory(self):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setSpacing(10)
        if self.demo:
            banner = plain_label("DEMO · Fictional sample inventory · No network discovery")
            font = banner.font()
            font.setBold(True)
            banner.setFont(font)
            layout.addWidget(banner)
        self.summary = plain_label("")
        font = self.summary.font()
        font.setPointSize(font.pointSize() + 2)
        font.setBold(True)
        self.summary.setFont(font)
        layout.addWidget(self.summary)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search assets, or enter an IP range such as 10.0.0.0/24…")
        self.search.setClearButtonEnabled(True)
        self.search.setAccessibleName("Search assets")
        self.search_timer = QTimer(self)
        self.search_timer.setSingleShot(True)
        self.search_timer.setInterval(120)
        self.search_timer.timeout.connect(self.apply_filters)
        self.search.textChanged.connect(lambda: self.search_timer.start())
        self.search.returnPressed.connect(self.apply_filters)
        layout.addWidget(self.search)
        row = QGridLayout()
        self.filters = {}
        for index, (key, title) in enumerate((("Risk", "All risks"), ("Tag", "All device types"), ("Source", "All sources"), ("AgentCapable", "Any agent capability"), ("Environment", "All environments"))):
            combo = QComboBox()
            combo.setMinimumContentsLength(10)
            combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
            combo.setAccessibleName(title)
            combo.addItem(title, None)
            if key == "Risk":
                for risk in RISK_COLOURS:
                    combo.addItem(risk, risk)
            elif key == "AgentCapable":
                combo.addItem("Agent capable", True)
                combo.addItem("Not agent capable", False)
            combo.currentIndexChanged.connect(self.apply_filters)
            self.filters[key] = combo
            row.addWidget(combo, index // 3, index % 3)
        self.reset_filters_button = QPushButton("Reset filters")
        self.reset_filters_button.clicked.connect(self.reset_filters)
        row.addWidget(self.reset_filters_button, 1, 2)
        layout.addLayout(row)
        actions = QHBoxLayout()
        self.identify_button = QPushButton("Identify selected")
        self.identify_button.setToolTip("Check this device's common TCP ports, OS and service hints using a Standard scan.")
        self.identify_button.clicked.connect(self.identify_selected)
        actions.addWidget(self.identify_button)
        self.clear_results_button = QPushButton("Clear results…")
        self.clear_results_button.setEnabled(not self.demo)
        self.clear_results_button.clicked.connect(self.clear_inventory)
        actions.addWidget(self.clear_results_button)
        actions.addStretch()
        actions.addWidget(plain_label("Export:"))
        self.export_buttons = {}
        for fmt in ("csv", "html", "json"):
            button = QPushButton(fmt.upper())
            button.setAccessibleName(f"Export visible results as {fmt.upper()}")
            button.setToolTip(f"Save the currently visible results as {fmt.upper()}")
            button.clicked.connect(lambda checked=False, fmt=fmt: self.export_dialog(fmt))
            actions.addWidget(button)
            self.export_buttons[fmt] = button
        layout.addLayout(actions)
        self.selection_hint = plain_label("Select a device to identify it. Hover over OS, ports or device type to see evidence.")
        layout.addWidget(self.selection_hint)
        self.model = InventoryModel(self)
        self.proxy = InventoryFilter(self)
        self.proxy.setSourceModel(self.model)
        self.table = QTableView()
        self.table.setAccessibleName("Discovered assets; press Enter for details")
        self.table.setModel(self.proxy)
        self.table.selectionModel().selectionChanged.connect(lambda *_: self.update_identify_button())
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().hide()
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 135)
        self.table.setColumnWidth(1, 160)
        self.table.setColumnWidth(2, 195)
        self.table.setColumnWidth(3, 155)
        # activated covers Enter and the platform's normal activation gesture.
        # Connecting doubleClicked too would open the same modal dialog twice.
        self.table.activated.connect(self.show_asset)
        self.empty = plain_label("Start a discovery or import a CSV, JSON or Discovr HTML report.")
        layout.addWidget(self.empty)
        self.welcome = QWidget()
        welcome_row = QHBoxLayout(self.welcome)
        welcome_row.setContentsMargins(0, 0, 0, 0)
        for title, callback in (("1. Use local subnet", self.detect_subnet), ("Explore sample inventory", self.show_demo), ("Import report…", self.import_dialog)):
            button = QPushButton(title)
            button.clicked.connect(callback)
            welcome_row.addWidget(button)
        layout.addWidget(self.welcome)
        vertical = QSplitter(Qt.Orientation.Vertical)
        vertical.addWidget(self.table)
        tabs = QTabWidget()
        scans = QWidget()
        scan_layout = QVBoxLayout(scans)
        self.scan_status = plain_label("No scans yet. Your first results will appear above.")
        scan_layout.addWidget(self.scan_status)
        self.progress = QProgressBar()
        self.progress.setAccessibleName("Discovery progress")
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setMaximumHeight(6)
        scan_layout.addWidget(self.progress)
        self.jobs = QTableWidget(0, 5)
        self.jobs.currentCellChanged.connect(lambda *_: self.refresh())
        self.jobs.setHorizontalHeaderLabels(["Discovery", "Status", "Progress", "Assets", "Job ID"])
        self.jobs.setColumnHidden(4, True)
        self.jobs.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.jobs.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.jobs.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.jobs.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.jobs.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.jobs.verticalHeader().hide()
        self.jobs.itemDoubleClicked.connect(self.show_job)
        scan_layout.addWidget(self.jobs)
        buttons = QHBoxLayout()
        self.stop_button = QPushButton("Stop selected")
        self.stop_button.clicked.connect(self.stop_selected)
        buttons.addWidget(self.stop_button)
        self.stop_all_button = QPushButton("Stop all")
        self.stop_all_button.clicked.connect(self.session.stop_all)
        buttons.addWidget(self.stop_all_button)
        details = QPushButton("Scan details…")
        details.clicked.connect(self.show_job)
        buttons.addWidget(details)
        buttons.addStretch()
        scan_layout.addLayout(buttons)
        tabs.addTab(scans, "Scans")
        self.activity = QPlainTextEdit()
        self.activity.setReadOnly(True)
        self.activity.setMaximumBlockCount(500)
        tabs.addTab(self.activity, "Activity")
        vertical.addWidget(tabs)
        tabs.setVisible(not self.demo)
        vertical.setSizes([430, 190])
        layout.addWidget(vertical, 1)
        layout.addWidget(plain_label("Double-click for full details. Remote OS, device type, risk and agent capability use available evidence; unknown exposure does not mean isolated."))
        return container

    def target_changed(self, _text):
        self._target_revision += 1

    def detect_subnet(self, checked=False, *, initial=False):
        if self.demo or self.session.closed or self._detecting_network:
            return
        self._detecting_network = True
        revision = self._target_revision
        fill_target = not initial or not self.fields["network"]["target"].text().strip()
        self.detect_button.setEnabled(False)
        self.detect_button.setText("Detecting…")
        self.local_connection.setEnabled(False)
        self.local_network_status.setText("Reading this computer's connections…")

        def detect():
            try:
                from discovr.network import local_network_info
                info, error = local_network_info(), None
            except Exception as exc:
                info, error = None, exc
            try:
                self.preparation.network_detected.emit(info, error, revision, fill_target)
            except RuntimeError:
                pass  # The native window may have been destroyed while the OS was reading.

        threading.Thread(target=detect, daemon=True, name="discovr-local-ip").start()

    def network_detected(self, info, error, revision, fill_target):
        self._detecting_network = False
        if self.session.closed:
            return
        self.detect_button.setEnabled(True)
        self.detect_button.setText("Use local subnet")
        self.local_connection.blockSignals(True)
        self.local_connection.clear()
        connections = info["connections"] if info else []
        selected = info["selected"] if info else None
        if error or not connections:
            self.local_connection.addItem("No local IPv4 detected")
            self.local_network_status.setText("Connect to a network and try Use local subnet, or enter a target manually.")
        else:
            self.local_connection.addItem("Choose a local connection", None)
            for connection in connections:
                self.local_connection.addItem(f"{connection['ip']} · {connection['interface']}", connection)
            self.local_connection.setCurrentIndex(selected + 1 if selected is not None else 0)
            self.local_network_status.setText("Choose the connection you want to discover." if selected is None
                                             else "Local IP detected. Review the target before starting.")
        self.local_connection.blockSignals(False)
        self.local_connection.setEnabled(bool(connections) and not error)
        # A late startup result must not replace a target typed or selected meanwhile.
        if selected is not None and fill_target and revision == self._target_revision:
            self.local_connection_selected()

    def local_connection_selected(self, _index=None):
        connection = self.local_connection.currentData()
        if self.session.closed or not connection:
            return
        self.fields["network"]["target"].setText(connection["subnet"])
        self.local_network_status.setText("Local IP detected. Review the target before starting." if connection["netmask_known"]
                                         else "Subnet mask unavailable; only this computer is selected. You can edit the target.")

    def browse_file(self, edit):
        path, _ = QFileDialog.getOpenFileName(self, "Choose a file", self.last_folder)
        if path:
            edit.setText(path)
            self.last_folder = str(Path(path).parent)

    def start_scan(self):
        if self.demo or self._preparing:
            return
        kind = self.source.currentData()
        params = {"environment": self.environment.text()}
        for key, widget in self.fields[kind].items():
            params[key] = (widget.text() if isinstance(widget, QLineEdit) else
                           widget.isChecked() if isinstance(widget, QCheckBox) else
                           widget.value() if isinstance(widget, QSpinBox) else widget.currentData())
        self._preparing = True
        self.start_button.setText("Preparing discovery…")
        self.start_button.setEnabled(False)
        self.forms.setEnabled(False)
        self.source.setEnabled(False)
        self.form_error.clear()

        def prepare():
            # Provider imports and credential-file checks can touch slow disks. They
            # belong off the GUI thread, just like scanning. Signals cross back safely.
            try:
                job, error = self.session.start(kind, params), None
            except Exception as exc:
                job, error = None, exc
            finally:
                params.clear()
            self.preparation.finished.emit(kind, job, error)

        threading.Thread(target=prepare, daemon=True, name="discovr-prepare").start()

    def scan_prepared(self, kind, job, error):
        self._preparing = False
        if self.session.closed:
            return
        self.start_button.setText("Start discovery")
        self.forms.setEnabled(True)
        self.source.setEnabled(True)
        self.refresh()
        if error:
            self.form_error.setText(str(error) or type(error).__name__)
            field = self.fields[kind].get(getattr(error, "field", None))
            if field is not None:
                # Advanced fields are revealed before focusing a validation error.
                if kind == "network" and field.parentWidget() is self.advanced_panel:
                    self.advanced_button.setChecked(True)
                field.setFocus()
                self.forms.currentWidget().ensureWidgetVisible(field)
            return
        for field in self.secret_fields:
            if field in self.fields[kind].values():
                field.clear()
        self.form_error.clear()
        self.statusBar().showMessage(f"Started {job['label']}")
        self.refresh()
        self.jobs.selectRow(self.jobs.rowCount() - 1)

    def refresh(self):
        # Bulk imports can hold the inventory lock. Skip one refresh rather than
        # blocking keyboard input behind a worker; the next timer tick catches up.
        if not self.session.lock.acquire(blocking=False):
            return
        try:
            snapshot = self.session.snapshot(self.version, self.activity_seq)
        finally:
            self.session.lock.release()
        if snapshot["assets"] is not None:
            self.version = snapshot["version"]
            self.proxy.setDynamicSortFilter(False)
            self.model.replace(snapshot["assets"], snapshot["keys"])
            self.proxy.setDynamicSortFilter(True)
            for key in ("Tag", "Source", "Environment"):
                combo = self.filters[key]
                selected = combo.currentData()
                values = set()
                for asset in self.model.assets:
                    value = str(asset.get(key) or "")
                    values.update(v.strip() for v in (value.replace(";", ",").split(",") if key == "Source" else [value]) if v.strip())
                if values == {combo.itemData(i) for i in range(1, combo.count())}:
                    continue
                combo.blockSignals(True)
                while combo.count() > 1:
                    combo.removeItem(1)
                for value in sorted(values):
                    combo.addItem(value.strip("[]"), value)
                index = combo.findData(selected)
                combo.setCurrentIndex(max(0, index))
                combo.blockSignals(False)
            self.apply_filters()
            self.setWindowModified(self.version != self.saved_version and bool(self.model.assets))
        jobs = snapshot["jobs"]
        signature = json.dumps(jobs, sort_keys=True)
        if signature != self._jobs_signature:
            selected = self.selected_job_id()
            self._jobs_signature = signature
            self.jobs.blockSignals(True)
            self.jobs.setRowCount(len(jobs))
            for row, job in enumerate(jobs):
                progress = f"{job['stage']} ({job['done']}/{job['total']})" if job["total"] else job["stage"]
                status = "Incomplete" if job["status"] == "partial" else job["status"].title()
                for col, value in enumerate((job["label"], status, progress, job["found"], job["id"])):
                    item = QTableWidgetItem(str(value))
                    item.setToolTip("\n".join([job.get("error") or ""] + job.get("warnings", [])))
                    self.jobs.setItem(row, col, item)
                if job["id"] == selected:
                    self.jobs.selectRow(row)
            self.jobs.blockSignals(False)
        running = sum(j["status"] == "running" for j in jobs)
        self.start_button.setEnabled(running < 4 and not self._preparing and not self.demo)
        self.update_identify_button()
        self.stop_all_button.setEnabled(bool(running))
        selected = next((j for j in jobs if j["id"] == self.selected_job_id()), jobs[-1] if jobs else None)
        self.stop_button.setEnabled(bool(selected and selected["status"] == "running"))
        if selected:
            elapsed = (selected["finished"] or time.time()) - selected["started"]
            attention = selected.get("error") or "; ".join(selected.get("warnings", []))
            self.scan_status.setText(f"{selected['label']} · {selected['stage']} · {selected['found']:,} assets · {elapsed:.0f}s"
                                     + (f"\nNeeds attention: {attention}" if attention else ""))
            total = selected["total"]
            self.progress.setRange(0, total or (0 if selected["status"] == "running" else 1))
            self.progress.setValue(selected["done"] if total else 1)
        for entry in snapshot["activity"]:
            stamp = datetime.fromtimestamp(entry["time"]).strftime("%H:%M:%S")
            self.activity.appendPlainText(f"{stamp}  {entry['level'].upper()}  {entry['message']}")
            self.activity_seq = entry["seq"]

    def apply_filters(self, *_):
        self.search_timer.stop()
        self.proxy.beginFilterChange()
        self.proxy.query = self.search.text().strip().casefold()
        try:
            self.proxy.subnet = ipaddress.ip_network(self.proxy.query, strict=False) if "/" in self.proxy.query else None
        except ValueError:
            self.proxy.subnet = None
        self.proxy.criteria = {key: combo.currentData() for key, combo in self.filters.items()}
        self.proxy.endFilterChange()
        assets = self.visible_assets()
        capable = sum(a.get("AgentCapable") is True for a in assets)
        urgent = sum(a.get("Risk") in ("Critical", "High") for a in assets)
        self.summary.setText(f"{len(assets):,} of {len(self.model.assets):,} assets   ·   {capable:,} agent capable   ·   {urgent:,} high / critical")
        self.empty.setVisible(not assets)
        self.empty.setText("No assets match these filters." if self.model.assets else "Start a discovery or import a CSV, JSON or Discovr HTML report.")
        self.welcome.setVisible(not self.model.assets and not self.demo)

    def reset_filters(self):
        self.search.clear()
        for combo in self.filters.values():
            combo.blockSignals(True)
            combo.setCurrentIndex(0)
            combo.blockSignals(False)
        self.apply_filters()

    def update_identify_button(self):
        index = self.table.currentIndex()
        asset = self.model.assets[self.proxy.mapToSource(index).row()] if index.isValid() else {}
        try:
            ipaddress.IPv4Address(asset.get("IP", ""))
            valid = not asset.get("Cloud")
        except (ValueError, TypeError):
            valid = False
        self.identify_button.setEnabled(valid and not self.demo and not self._preparing)
        if asset:
            evidence = asset.get("PortStatus") or ("Ports not checked" if is_blank(asset.get("Ports")) else "Recorded port information")
            os_status = asset.get("OSConfidence") or ("OS not identified" if is_blank(asset.get("OS")) else "Recorded OS information")
            self.selection_hint.setText(f"{asset.get('IP') or asset.get('Hostname', 'Selected device')} · {os_status} · {evidence}")
        else:
            self.selection_hint.setText("Select a device to identify it. Hover over OS, ports or device type to see evidence.")

    def identify_selected(self):
        index = self.table.currentIndex()
        if not index.isValid() or self.demo or self._preparing:
            return
        asset = self.model.assets[self.proxy.mapToSource(index).row()]
        self.source.setCurrentIndex(self.source.findData("network"))
        self.fields["network"]["target"].setText(asset["IP"])
        self.fields["network"]["ports"].clear()
        self.fields["network"]["depth"].setCurrentIndex(0)
        self.environment.setText(str(asset.get("Environment") or ""))
        self.start_scan()

    def visible_assets(self):
        return [self.model.assets[self.proxy.mapToSource(self.proxy.index(row, 0)).row()]
                for row in range(self.proxy.rowCount())]

    def selected_job_id(self):
        item = self.jobs.item(self.jobs.currentRow(), 4)
        return item.text() if item else None

    def stop_selected(self):
        job_id = self.selected_job_id()
        if job_id:
            try:
                self.session.cancel(job_id)
            except BadRequest as exc:
                self.statusBar().showMessage(str(exc))
            self.refresh()

    def text_dialog(self, title, content):
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.resize(680, 460)
        layout = QVBoxLayout(dialog)
        text = QPlainTextEdit()
        text.setReadOnly(True)
        text.setPlainText(content)
        layout.addWidget(text)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        dialog.exec()

    def show_job(self, *_):
        job_id = self.selected_job_id()
        job = next((j for j in self.session.snapshot(self.version)["jobs"] if j["id"] == job_id), None)
        if job:
            content = f"{job['label']}\nStatus: {job['status']}\n{job['stage']}\nAssets found: {job['found']}"
            if job["error"]:
                content += f"\n\nError\n{job['error']}"
            if job["warnings"]:
                content += "\n\nWarnings\n" + "\n\n".join(job["warnings"])
            self.text_dialog("Scan details", content)

    def show_asset(self, index):
        if index.isValid():
            asset = self.model.assets[self.proxy.mapToSource(index).row()]
            self.text_dialog("Asset details", "\n\n".join(f"{LABELS.get(key, key)}\n{_cell_text(value) if value is not None else 'Unknown'}"
                                                         for key, value in asset.items()))

    def import_path(self, path):
        count = self.read_report(path)
        self.last_folder = str(Path(path).parent)
        self.refresh()
        self.statusBar().showMessage(f"Imported {count:,} assets")
        return count

    def read_report(self, path):
        """Disk parsing and merge are safe in a worker; no widgets are touched here."""
        from discovr.reports import read_report
        return self.session.import_report(read_report(path))

    def import_dialog(self):
        if self._importing or self.demo:
            return
        path, _ = QFileDialog.getOpenFileName(self, "Import report to view or convert", self.last_folder,
                                            "Discovr reports (*.json *.csv *.html *.htm);;JSON (*.json);;CSV (*.csv);;Discovr HTML (*.html *.htm)")
        if path:
            self._importing = True
            self.statusBar().showMessage("Importing report… You can continue using the inventory.")
            def load():
                try:
                    count, error = self.read_report(path), None
                except Exception as exc:
                    count, error = None, exc
                self.preparation.imported.emit(path, count, error)
            threading.Thread(target=load, daemon=True, name="discovr-import").start()

    def import_finished(self, path, count, error):
        self._importing = False
        if self.session.closed:
            return
        if error:
            self.error("Could not import report", str(error))
        else:
            self.last_folder = str(Path(path).parent)
            self.refresh()
            self.statusBar().showMessage(f"Imported {count:,} assets")

    def export_path(self, path, fmt, all_assets=False):
        self.apply_filters()  # A click can arrive before the search debounce expires.
        snapshot = self.session.snapshot()
        assets = snapshot["assets"] if all_assets else self.visible_assets()
        write_report(path, assets, fmt)
        if all_assets and fmt == "json":
            # A worker may have merged more assets during disk I/O. Only mark this snapshot saved.
            self.saved_version = snapshot["version"]
            self.setWindowModified(self.session.version != self.saved_version)
        self.last_folder = str(Path(path).parent)
        self.statusBar().showMessage(f"Saved {len(assets):,} assets to {Path(path).name}")
        return True

    def save_inventory(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save complete inventory", str(Path(self.last_folder) / "discovr-inventory.json"), "JSON reports (*.json)")
        if not path:
            return False
        try:
            return self.export_path(path if Path(path).suffix else path + ".json", "json", all_assets=True)
        except (OSError, ValueError) as exc:
            self.error("Could not save inventory", str(exc))
            return False

    def export_dialog(self, fmt=None):
        self.apply_filters()
        choices = {"CSV spreadsheet (*.csv)": "csv", "JSON report (*.json)": "json", "HTML report (*.html)": "html"}
        if fmt not in FORMATS:
            fmt = None  # QAction.triggered can pass a boolean.
        filters = ";;".join(k for k, v in choices.items() if not fmt or v == fmt)
        path, selected = QFileDialog.getSaveFileName(self, f"Export {self.proxy.rowCount():,} visible assets", str(Path(self.last_folder) / ("discovr-report" + ("." + fmt if fmt else ""))), filters)
        if path:
            fmt = fmt or choices.get(selected, "csv")
            try:
                if Path(path).suffix and Path(path).suffix.lower() != "." + fmt:
                    raise ValueError(f"Use a .{fmt} filename for a {fmt.upper()} report.")
                self.export_path(path if Path(path).suffix else path + "." + fmt, fmt)
            except (OSError, ValueError) as exc:
                self.error("Could not export report", str(exc))

    def error(self, title, message):
        box = QMessageBox(QMessageBox.Icon.Warning, title, message, QMessageBox.StandardButton.Ok, self)
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.exec()

    def clear_inventory(self):
        if self.demo:
            return
        if self._preparing:
            self.error("Discovery is preparing", "Wait for preparation to finish, then clear the results.")
            return
        if self._importing:
            self.error("Import is running", "Wait for the import to finish before clearing the inventory.")
            return
        answer = QMessageBox.question(self, "Clear results", "Stop running scans and clear all results, including hidden rows? Saved report files will be kept.",
                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if answer == QMessageBox.StandardButton.Yes:
            self.session.clear(stop_running=True)
            self.refresh()
            self.reset_filters()
            self.statusBar().showMessage("Results cleared. Saved reports are unchanged.")

    def show_demo(self):
        if self.demo:
            self.reset_filters()
            return self
        # A separate Session makes sample exports useful without contaminating real scans.
        demo = MainWindow(demo=True)
        self.demo_windows.append(demo)
        demo.show()
        return demo

    def show_integration(self):
        if self.demo:
            self.statusBar().showMessage("API integration is unavailable in the sample inventory.")
            return
        from discovr.integration import IntegrationDialog
        if self.integration is None:
            self.integration = IntegrationDialog(self.session, self)
        self.integration.show()
        self.integration.raise_()

    def show_help(self):
        self.text_dialog("Using Discovr", "1. Your local IPv4 address and connection appear automatically under Network. Review the prepared subnet, choose another connection or edit the target. Use local subnet refreshes after network changes. No scan starts automatically.\n\n"
                         "2. Results arrive in the inventory. Up to four scans can run together. Stop selected preserves assets already found. "
                         "Double-click a scan to inspect warnings and incomplete results.\n\n"
                         "Select a device and choose Identify selected for a Standard check of that address. Hover over OS, ports and device type for evidence.\n\n"
                         "Reset filters shows all rows. Clear results stops scans and removes every row after confirmation. Saved files are kept.\n\n"
                         "Convert a report: import CSV, JSON or a new Discovr HTML report into an empty inventory, then click CSV, HTML or JSON above the table.\n\n"
                         "3. Search or filter results. Double-click an asset to inspect every field.\n\n"
                         "Enter a CIDR such as 10.0.0.0/24 in Search to group a range. Add an Environment label before discovery to group results by client or location.\n\n"
                         "4. Export view saves filtered results as CSV, JSON or HTML. Save inventory saves every asset as JSON, regardless of filters. "
                         "Import report merges a CSV, JSON or Discovr HTML report into this session.\n\n"
                         "5. Close the app before ejecting your USB drive. Results and credentials are kept in memory; save results you want to retain.\n\n"
                         "Help > Explore sample inventory opens fictional examples in a separate window without scanning. Tools > Local API integration enables an optional, authenticated loopback API for your integrations.\n\n"
                         "Local discovery works offline. Cloud and AD require network access and authorised credentials. "
                         "Risk and agent capability are triage estimates, not vulnerability verification. "
                         "Neighbour-cache observation is passive and cannot establish current liveness.")

    def show_licences(self):
        path = Path(__file__).with_name("THIRD_PARTY_NOTICES.txt")
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            content = "Third-party notices are generated when building the USB app. See requirements.lock for exact dependency versions."
        self.text_dialog("Third-party licences", content)

    def about(self):
        self.text_dialog("About Discovr", f"Discovr {__version__}\nPortable asset discovery\n\n"
                         "Native desktop software for Windows, Linux and macOS.\n"
                         "Python and Qt are bundled; no additional software is required.\n\n"
                         "Qt / PySide6 are dynamically linked under LGPLv3. See Third-party licences for notices and source locations.")

    def closeEvent(self, event):
        if not self._allow_close:
            if self._preparing or self._importing or any(j["status"] == "running" for j in self.session.snapshot(self.version)["jobs"]):
                answer = QMessageBox.question(self, "Stop work and quit?", "Running scans and imports will stop. Only results already received can be saved.",
                                              QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
                if answer != QMessageBox.StandardButton.Yes:
                    event.ignore()
                    return
                self.session.stop_all()
            snapshot = self.session.snapshot()
            if snapshot["assets"] and snapshot["version"] != self.saved_version:
                answer = QMessageBox.question(self, "Save inventory before closing?", "Save the complete inventory as a JSON report?",
                                              QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel,
                                              QMessageBox.StandardButton.Save)
                if answer == QMessageBox.StandardButton.Cancel or (answer == QMessageBox.StandardButton.Save and not self.save_inventory()):
                    event.ignore()
                    return
        self.session.close()
        if self.integration:
            self.integration.stop()
        for field in self.secret_fields:
            field.clear()
        self.timer.stop()
        if not self.demo:
            self.app_logger.removeHandler(self.log_handler)
            self.app_logger.setLevel(self.previous_log_level)
        self.log_handler.close()
        event.accept()
