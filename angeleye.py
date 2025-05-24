import sys
import os
import subprocess
import winreg
import getpass
import win32security
import ctypes
from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QVBoxLayout,
    QHBoxLayout, QFileDialog, QMessageBox, QComboBox, QLineEdit, QTextEdit
)
from PySide6.QtGui import QPixmap
from PySide6.QtCore import Qt

def get_local_users():
    import win32net
    resume = 0
    users = []
    while True:
        data, total, resume = win32net.NetUserEnum(None, 1, 2, resume)
        for user in data:
            name = user['name']
            flags = user['flags']
            
            # Skip disabled accounts (UF_ACCOUNTDISABLE = 0x0002)
            # Skip built-in/system accounts
            if flags & 0x0002:
                continue
            users.append(name)

        if not resume:
            break
    return users

def get_user_sid(username):
    domain = os.environ['COMPUTERNAME']
    sid, _, _ = win32security.LookupAccountName(domain, username)
    return win32security.ConvertSidToStringSid(sid)

def is_hive_loaded(sid):
    try:
        winreg.OpenKey(winreg.HKEY_USERS, sid)
        return True
    except FileNotFoundError:
        return False

def load_user_hive(username, sid, mount_as):
    user_profile = fr"C:\\Users\\{username}"
    ntuser_path = os.path.join(user_profile, "NTUSER.DAT")
    if not os.path.exists(ntuser_path):
        raise FileNotFoundError(f"NTUSER.DAT not found for '{username}'")
    subprocess.run(["reg", "load", f"HKU\\{mount_as}", ntuser_path], check=True)

def unload_user_hive(mount_as):
    subprocess.run(["reg", "unload", f"HKU\\{mount_as}"], check=True)

def reg_type_from_str(type_str):
    mapping = {
        "REG_SZ": winreg.REG_SZ,
        "SZ": winreg.REG_SZ,
        "REG_DWORD": winreg.REG_DWORD,
        "DWORD": winreg.REG_DWORD
    }
    return mapping.get(type_str.upper(), winreg.REG_SZ)

def parse_lgpo_txt(path):
    with open(path, "r", encoding="cp1252", errors="replace") as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith(";")]

    settings = {}
    i = 0
    while i < len(lines):
        if lines[i] in ["Computer", "User"]:
            i += 1
            key_path = lines[i]
            i += 1
            while i + 1 < len(lines) and lines[i] not in ["Computer", "User"]:
                name = lines[i]
                data_line = lines[i + 1]
                i += 2

                if name == "*" and data_line in ["DELETEALLVALUES", "CREATEKEY"]:
                    continue

                if ":" not in data_line:
                    continue

                reg_type, value = data_line.split(":", 1)
                reg_type = reg_type.strip()
                value = value.strip()

                if key_path not in settings:
                    settings[key_path] = {}

                if reg_type.upper() == "DWORD":
                    value = int(value)
                settings[key_path][name] = {"type": reg_type, "value": value}
        else:
            i += 1
    return settings

def apply_registry_settings(settings, mount_as, log_fn):
    for subkey, values in settings.items():
        try:
            if subkey.startswith("HKLM\\"):
                key_path = subkey[5:]  # Remove 'HKLM\\'
                key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            else:
                key_path = f"{mount_as}\\{subkey}"
                key = winreg.CreateKey(winreg.HKEY_USERS, key_path)

            for name, entry in values.items():
                reg_type = reg_type_from_str(entry["type"])
                value = entry["value"]
                winreg.SetValueEx(key, name, 0, reg_type, value)

            winreg.CloseKey(key)
            log_fn(f"✔ Applied: {subkey}")
        except Exception as e:
            log_fn(f"❌ Failed to apply {subkey}: {e}")

def apply_policy(username, file_path, log_fn):
    try:
        sid = get_user_sid(username)
        hive_loaded = is_hive_loaded(sid)
        mount_as = sid if hive_loaded else "TempHive"

        if not hive_loaded:
            load_user_hive(username, sid, mount_as)

        settings = parse_lgpo_txt(file_path)
        apply_registry_settings(settings, mount_as, log_fn)

        if not hive_loaded:
            unload_user_hive(mount_as)

        subprocess.run(["gpupdate", "/force"], check=True)
        log_fn("✔ gpupdate /force executed")
        return f"Policy successfully applied to {username}"
    except Exception as e:
        log_fn(f"❌ {str(e)}")
        return str(e)

def check_policy(settings, mount_as, log_fn):
    all_match = True
    for subkey, values in settings.items():
        try:
            if subkey.startswith("HKLM\\"):
                key_path = subkey[5:]  # Enlève "HKLM\"
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            else:
                key_path = f"{mount_as}\\{subkey}"
                key = winreg.OpenKey(winreg.HKEY_USERS, key_path)

            for name, entry in values.items():
                expected_type = reg_type_from_str(entry["type"])
                expected_value = entry["value"]

                try:
                    value, val_type = winreg.QueryValueEx(key, name)
                    if value != expected_value or val_type != expected_type:
                        log_fn(f"❌ Mismatch: {subkey}\\{name} (Expected: {expected_value}, Found: {value})")
                        all_match = False
                    else:
                        log_fn(f"✔ Match: {subkey}\\{name}")
                except FileNotFoundError:
                    log_fn(f"❌ Missing value: {subkey}\\{name}")
                    all_match = False

            winreg.CloseKey(key)

        except FileNotFoundError:
            log_fn(f"❌ Missing key: {subkey}")
            all_match = False

    return all_match


class LGPOGui(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Angel Eye")
        self.setGeometry(100, 100, 600, 400)
        self.init_ui()

    def init_ui(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.policy_dir = os.path.join(base_dir, "resources", "Policies")
        logo_path = os.path.join(base_dir, "resources", "images", "logo.png")

        layout = QVBoxLayout()

        # Load and display logo
        if os.path.exists(logo_path):
            logo_label = QLabel()
            pixmap = QPixmap(logo_path)
            pixmap = pixmap.scaledToWidth(300)  # Optional: resize logo
            logo_label.setPixmap(pixmap)
            logo_label.setAlignment(Qt.AlignCenter)
            layout.addWidget(logo_label)

        # User selection
        layout.addWidget(QLabel("Select User:"))
        self.user_combo = QComboBox()
        self.user_combo.addItems(get_local_users())
        layout.addWidget(self.user_combo)

        # Policy selection from folder
        layout.addWidget(QLabel("Select Policy File:"))
        self.policy_combo = QComboBox()
        self.load_policy_files()
        layout.addWidget(self.policy_combo)

        button_layout = QHBoxLayout()

        apply_button = QPushButton("Apply Policy")
        apply_button.clicked.connect(self.on_apply_clicked)
        button_layout.addWidget(apply_button)

        check_button = QPushButton("Check Policy")
        check_button.clicked.connect(self.on_check_clicked)
        button_layout.addWidget(check_button)

        layout.addLayout(button_layout)

        # Console log
        layout.addWidget(QLabel("Console log:"))
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        layout.addWidget(self.log_output)

        self.setLayout(layout)

    def load_policy_files(self):
        self.policy_combo.clear()
        if os.path.isdir(self.policy_dir):
            for file in os.listdir(self.policy_dir):
                if file.lower().endswith(".txt"):
                    self.policy_combo.addItem(file)
        else:
            self.log_output.append(f"⚠ Policies folder not found: {self.policy_dir}")

    def log(self, message):
        self.log_output.append(message)

    def on_apply_clicked(self):
        username = self.user_combo.currentText()
        selected_file = self.policy_combo.currentText()
        if not selected_file:
            QMessageBox.warning(self, "Missing Policy", "No policy file selected.")
            return

        file_path = os.path.join(self.policy_dir, selected_file)
        self.log_output.clear()
        result = apply_policy(username, file_path, self.log)
        QMessageBox.information(self, "Result", result)

    def on_check_clicked(self):
        self.log_output.clear()
        username = self.user_combo.currentText()
        selected_file = self.policy_combo.currentText()
        if not selected_file:
            QMessageBox.warning(self, "Missing Policy", "No policy file selected.")
            return
        file_path = os.path.join(self.policy_dir, selected_file)
        try:
            sid = get_user_sid(username)
            hive_loaded = is_hive_loaded(sid)
            mount_as = sid if hive_loaded else "TempHive"
            if not hive_loaded:
                load_user_hive(username, sid, mount_as)

            settings = parse_lgpo_txt(file_path)
            result = check_policy(settings, mount_as, self.log)

            if not hive_loaded:
                unload_user_hive(mount_as)

            QMessageBox.information(self, "Check Result", "✔ All settings match." if result else "❌ Some settings differ.")
        except Exception as e:
            self.log(f"❌ {e}")
            QMessageBox.critical(self, "Error", str(e))


if __name__ == "__main__":
    if not ctypes.windll.shell32.IsUserAnAdmin():
        # Relaunch as admin
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            sys.exit()
    app = QApplication(sys.argv)
    gui = LGPOGui()
    gui.show()
    sys.exit(app.exec())