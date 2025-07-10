#!/usr/bin/env python3
import os
import sys
import tempfile
import shutil
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Import core VaultAES functions
import vault_audio_aes as va

class VaultGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VaultAES")
        self.resizable(False, False)
        self._build_widgets()
        self._layout_widgets()
        self._bind_events()
        self.mode_var.set("Lock")  # default mode

    def _build_widgets(self):
        # Operation selector
        self.mode_var = tk.StringVar()
        self.op_menu = ttk.Combobox(
            self, textvariable=self.mode_var,
            values=["Lock", "Unlock", "Change Password"],
            state="readonly"
        )

        # Folder lock checkbox (only in Lock mode)
        self.folder_var = tk.BooleanVar()
        self.chk_folder = ttk.Checkbutton(
            self, text="Lock entire folder", variable=self.folder_var
        )

        # File/Folder browser
        self.path_var = tk.StringVar()
        self.ent_path = ttk.Entry(self, textvariable=self.path_var, width=40, state="readonly")
        self.btn_browse = ttk.Button(self, text="Browse…", command=self._on_browse)

        # Password entries
        self.lbl_pass1 = ttk.Label(self, text="Password:")
        self.ent_pass1 = ttk.Entry(self, show="*", width=25)
        self.lbl_pass2 = ttk.Label(self, text="New Password:")
        self.ent_pass2 = ttk.Entry(self, show="*", width=25)

        # Action button & status label
        self.btn_action = ttk.Button(self, text="Go", command=self._perform)
        self.lbl_status = ttk.Label(self, text="", foreground="green")

    def _layout_widgets(self):
        pad = {"padx": 8, "pady": 4}
        ttk.Label(self, text="Operation:").grid(row=0, column=0, **pad, sticky="w")
        self.op_menu.grid(row=0, column=1, columnspan=2, **pad, sticky="ew")

        self.chk_folder.grid(row=1, column=0, columnspan=3, **pad, sticky="w")

        ttk.Label(self, text="Select:").grid(row=2, column=0, **pad, sticky="w")
        self.ent_path.grid(row=2, column=1, **pad, sticky="ew")
        self.btn_browse.grid(row=2, column=2, **pad)

        self.lbl_pass1.grid(row=3, column=0, **pad, sticky="w")
        self.ent_pass1.grid(row=3, column=1, columnspan=2, **pad, sticky="ew")

        self.lbl_pass2.grid(row=4, column=0, **pad, sticky="w")
        self.ent_pass2.grid(row=4, column=1, columnspan=2, **pad, sticky="ew")

        self.btn_action.grid(row=5, column=0, columnspan=3, **pad)
        self.lbl_status.grid(row=6, column=0, columnspan=3, **pad)

    def _bind_events(self):
        # Update UI when the operation changes
        self.mode_var.trace_add("write", lambda *a: self._update_mode())

    def _update_mode(self):
        mode = self.mode_var.get()
        # Hide all optional controls
        self.chk_folder.grid_remove()
        self.lbl_pass2.grid_remove()
        self.ent_pass2.grid_remove()
        self.lbl_status.config(text="", foreground="green")

        # Show controls per mode
        if mode == "Lock":
            self.chk_folder.grid()
            self.lbl_pass1.config(text="Password:")
        elif mode == "Unlock":
            self.lbl_pass1.config(text="Password:")
        else:  # Change Password
            self.lbl_pass1.config(text="Old Password:")
            self.lbl_pass2.grid()
            self.ent_pass2.grid()

    def _on_browse(self):
        mode = self.mode_var.get()
        if mode == "Lock" and self.folder_var.get():
            path = filedialog.askdirectory()
        else:
            path = filedialog.askopenfilename()
        if path:
            self.path_var.set(path)

    def _clear_passwords(self):
        self.ent_pass1.delete(0, tk.END)
        self.ent_pass2.delete(0, tk.END)

    def _perform(self):
        mode = self.mode_var.get()
        src  = self.path_var.get().strip()
        pwd1 = self.ent_pass1.get().strip()
        pwd2 = self.ent_pass2.get().strip()

        if not mode or not src or not pwd1:
            return messagebox.showerror("Error", "Please fill in all required fields.")
        if not os.path.exists(src):
            return messagebox.showerror("Error", f"Path not found:\n{src}")

        try:
            if mode == "Lock":
                self._do_lock(src, pwd1)
            elif mode == "Unlock":
                self._do_unlock(src, pwd1)
            else:
                self._do_repass(src, pwd1, pwd2)
        except Exception as e:
            messagebox.showerror("Operation Failed", str(e))
        finally:
            self._clear_passwords()

    def _do_lock(self, src, pwd):
        if os.path.isdir(src):
            # Zip entire folder first
            base = os.path.basename(src.rstrip(os.sep))
            tmp_zip = os.path.join(tempfile.gettempdir(), f"{base}.zip")
            shutil.make_archive(tmp_zip[:-4], 'zip', src)
            vault_path = f"{src}.vault"
            va.lock(tmp_zip, vault_path, pwd)
            shutil.rmtree(src)
            os.remove(tmp_zip)
        else:
            vault_path = f"{src}.vault"
            va.lock(src, vault_path, pwd)
            os.remove(src)

        self.lbl_status.config(text=f"Locked → {vault_path}")

    def _do_unlock(self, src, pwd):
        data = open(src, "rb").read()
        meta, _ = va._split(data)
        dest = os.path.join(os.path.dirname(src), meta["orig"])
        va.unlock(src, dest, pwd)

        if os.path.exists(dest):
            self.lbl_status.config(text=f"Unlocked → {dest}")
        else:
            self.lbl_status.config(text="Wrong password or corrupted file.", foreground="red")

    def _do_repass(self, src, old, new):
        if not new:
            return messagebox.showerror("Error", "Please enter a new password.")

        # 1. Read header for original filename
        raw_blob = open(src, "rb").read()
        meta, _ = va._split(raw_blob)
        orig_name = meta["orig"]

        # 2. Decrypt into temp file with original name
        tmp_dir = tempfile.mkdtemp()
        tmp_path = os.path.join(tmp_dir, orig_name)
        try:
            va.unlock(src, tmp_path, old)
        except Exception:
            shutil.rmtree(tmp_dir)
            return messagebox.showerror("Error", "Old password incorrect or file corrupted.")

        if not os.path.exists(tmp_path):
            shutil.rmtree(tmp_dir)
            return messagebox.showerror("Error", "Old password incorrect or file corrupted.")

        # 3. Re-encrypt, preserving original name
        va.lock(tmp_path, src, new)

        # 4. Clean up
        shutil.rmtree(tmp_dir)
        self.lbl_status.config(text="Password changed successfully.")

if __name__ == "__main__":
    app = VaultGUI()
    app.mainloop()
