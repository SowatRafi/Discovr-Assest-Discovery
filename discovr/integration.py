"""Native controls for the optional local API; imported only on explicit user action."""
import threading

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QDialog, QDialogButtonBox, QFormLayout, QLineEdit, QPushButton

from discovr.server import create_server


class IntegrationDialog(QDialog):
    def __init__(self, session, parent):
        super().__init__(parent)
        from discovr.native import plain_label
        self.session = session
        self.server = None
        self.worker = None
        self.setWindowTitle("Local API integration")
        self.resize(560, 310)
        layout = QFormLayout(self)
        layout.addRow(plain_label("Connect your CMDB or other local software to this inventory. Disabled by default. Enabling allows authenticated local clients to read and change inventory and start scans."))
        self.status = plain_label("Disabled · No API listener")
        layout.addRow(self.status)
        self.url = QLineEdit()
        self.url.setReadOnly(True)
        self.url.setAccessibleName("Local API address")
        layout.addRow("Address", self.url)
        self.token = QLineEdit()
        self.token.setReadOnly(True)
        self.token.setEchoMode(QLineEdit.EchoMode.Password)
        self.token.setAccessibleName("Session API token")
        layout.addRow("Token", self.token)
        copy = QPushButton("Copy token")
        copy.clicked.connect(lambda: QApplication.clipboard().setText(self.token.text()))
        layout.addRow(copy)
        self.toggle = QPushButton("Enable local API")
        self.toggle.clicked.connect(self.toggle_server)
        layout.addRow(self.toggle)
        layout.addRow(plain_label("Send the token in X-Discovr-Token. GET /api/assets reads inventory. The API listens only on this computer and stops when Discovr closes. See the included API guide for all endpoints."))
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(self.hide)
        layout.addRow(close)
        self.timer = QTimer(self)
        self.timer.setInterval(250)
        self.timer.timeout.connect(self.refresh)
        self.timer.start()

    def start(self):
        if self.server is not None or self.session.closed:
            return
        server, url = create_server(session=self.session)
        self.server = server
        def run():
            try:
                server.serve_forever(poll_interval=0.1)
            finally:
                server.server_close()
        self.worker = threading.Thread(target=run, daemon=True, name="discovr-local-api")
        self.worker.start()
        self.url.setText(url)
        self.token.setText(server.token)
        self.status.setText("Enabled · Only authenticated clients on this computer can connect")
        self.toggle.setText("Disable local API")

    def stop(self):
        if self.server is not None:
            self.server.accepting = False
            # Shutdown waits for the serving thread: never run that wait on the UI thread.
            threading.Thread(target=self.server.shutdown, daemon=True).start()
        self.token.clear()
        self.url.clear()
        self.toggle.setEnabled(False)
        self.status.setText("Stopping local API…")

    def refresh(self):
        if self.worker is not None and not self.worker.is_alive():
            self.server = self.worker = None
            self.token.clear()
            self.url.clear()
            self.toggle.setEnabled(True)
            self.toggle.setText("Enable local API")
            self.status.setText("Disabled · No API listener")

    def toggle_server(self):
        if self.server is not None:
            self.stop()
        else:
            try:
                self.start()
            except OSError as exc:
                self.status.setText(f"Could not enable the API: {exc}")
