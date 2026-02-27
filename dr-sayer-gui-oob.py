#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import subprocess
import threading
import sys
import os

class DrSayerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Dr-Sayer GUI")
        self.root.geometry("900x650")
        self.url_var = tk.StringVar(value="http://localhost")
        self.sql_var = tk.BooleanVar(value=True)
        self.xss_var = tk.BooleanVar(value=True)
        self.log4j_var = tk.BooleanVar(value=True)
        self.waf_var = tk.BooleanVar(value=False)
        self.http_var = tk.BooleanVar(value=True)
        self.oob_var = tk.BooleanVar(value=False)
        self.all_var = tk.BooleanVar(value=False)
        self.format_var = tk.StringVar(value="html")
        self.output_var = tk.StringVar(value="")
        self.accept_var = tk.BooleanVar(value=False)
        self.attack_surface_ar = tk.StringVar(value="")
        self.attack_vector_ar = tk.StringVar(value="")
        self.oob_callback_var = tk.StringVar(value="oob.example.com")
        self.build_ui()

    def build_ui(self):
        top = ttk.Frame(self.root)
        top.pack(fill="x", padx=10, pady=10)
        ttk.Label(top, text="URL").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.url_var, width=60).grid(row=0, column=1, padx=5, sticky="ew")
        ttk.Button(top, text="اختيار ملف تقرير", command=self.browse_output).grid(row=0, column=2, padx=5)
        ttk.Label(top, text="اسم ملف التقرير").grid(row=1, column=0, sticky="w", pady=(8,0))
        ttk.Entry(top, textvariable=self.output_var, width=60).grid(row=1, column=1, padx=5, sticky="ew", pady=(8,0))
        tests = ttk.LabelFrame(self.root, text="الاختبارات")
        tests.pack(fill="x", padx=10, pady=5)
        ttk.Checkbutton(tests, text="تشغيل الكل", variable=self.all_var).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        ttk.Checkbutton(tests, text="SQL Injection", variable=self.sql_var).grid(row=1, column=0, padx=5, pady=5, sticky="w")
        ttk.Checkbutton(tests, text="XSS", variable=self.xss_var).grid(row=1, column=1, padx=5, pady=5, sticky="w")
        ttk.Checkbutton(tests, text="Log4j", variable=self.log4j_var).grid(row=1, column=2, padx=5, pady=5, sticky="w")
        ttk.Checkbutton(tests, text="WAF Bypass", variable=self.waf_var).grid(row=1, column=3, padx=5, pady=5, sticky="w")
        ttk.Checkbutton(tests, text="HTTP Inspector", variable=self.http_var).grid(row=1, column=4, padx=5, pady=5, sticky="w")
        ttk.Checkbutton(tests, text="OOB Attacks (SSTI/XXE/SSRF)", variable=self.oob_var).grid(row=1, column=5, padx=5, pady=5, sticky="w")
        ttk.Label(tests, text="OOB Callback:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(tests, textvariable=self.oob_callback_var, width=30).grid(row=2, column=1, columnspan=3, padx=5, pady=5, sticky="ew")
        fmt = ttk.LabelFrame(self.root, text="نسق التقرير")
        fmt.pack(fill="x", padx=10, pady=5)
        ttk.Radiobutton(fmt, text="HTML", variable=self.format_var, value="html").grid(row=0, column=0, padx=5, pady=5)
        ttk.Radiobutton(fmt, text="JSON", variable=self.format_var, value="json").grid(row=0, column=1, padx=5, pady=5)
        ttk.Radiobutton(fmt, text="TXT", variable=self.format_var, value="txt").grid(row=0, column=2, padx=5, pady=5)
        attack = ttk.LabelFrame(self.root, text="حقول عربية للتقرير")
        attack.pack(fill="both", padx=10, pady=5)
        ttk.Label(attack, text="سطح الاستغلال والهجوم").grid(row=0, column=0, sticky="w")
        self.surface_txt = tk.Text(attack, height=4)
        self.surface_txt.grid(row=1, column=0, columnspan=3, sticky="ew", pady=5)
        ttk.Label(attack, text="متجه الهجوم").grid(row=2, column=0, sticky="w")
        self.vector_txt = tk.Text(attack, height=4)
        self.vector_txt.grid(row=3, column=0, columnspan=3, sticky="ew", pady=5)
        ctrl = ttk.LabelFrame(self.root, text="التحكم")
        ctrl.pack(fill="x", padx=10, pady=5)
        ttk.Checkbutton(ctrl, text="أقرّ أن لدي تفويضاً وأنني أتحمل المسؤولية القانونية", variable=self.accept_var).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Button(ctrl, text="بدء الاختبار", command=self.start_test).grid(row=0, column=1, padx=5)
        ttk.Button(ctrl, text="فتح مجلد التقارير", command=self.open_reports_dir).grid(row=0, column=2, padx=5)
        out = ttk.LabelFrame(self.root, text="المخرجات")
        out.pack(fill="both", expand=True, padx=10, pady=10)
        self.log = scrolledtext.ScrolledText(out, font=("Consolas", 10))
        self.log.pack(fill="both", expand=True)

    def browse_output(self):
        fname = filedialog.asksaveasfilename(initialdir=os.path.join(os.path.dirname(__file__), "reports"),
                                             defaultextension=f".{self.format_var.get()}",
                                             filetypes=[("HTML","*.html"),("JSON","*.json"),("Text","*.txt"),("All","*.*")])
        if fname:
            self.output_var.set(fname)

    def open_reports_dir(self):
        path = os.path.join(os.path.dirname(__file__), "reports")
        try:
            os.makedirs(path, exist_ok=True)
            os.startfile(path)
        except Exception:
            messagebox.showinfo("المجلد", path)

    def start_test(self):
        if not self.accept_var.get():
            messagebox.showwarning("تنبيه", "يجب الموافقة على المسؤولية القانونية والتفويض.")
            return
        url = self.url_var.get().strip()
        if not url or not (url.startswith("http://") or url.startswith("https://")):
            messagebox.showwarning("عنوان غير صالح", "الرجاء إدخال رابط يبدأ بـ http:// أو https://")
            return
        surface = self.surface_txt.get("1.0", "end").strip()
        vector = self.vector_txt.get("1.0", "end").strip()
        fmt = self.format_var.get()
        out_file = self.output_var.get().strip()
        args = [sys.executable, "dr-sayer.py", "-u", url, "--accept-risk", "--report", fmt]
        if out_file:
            args += ["-o", out_file]
        if surface:
            args += ["--attack-surface-ar", surface]
        if vector:
            args += ["--attack-vector-ar", vector]
        if self.all_var.get():
            args += ["--all"]
        else:
            if self.sql_var.get():
                args += ["--sql"]
            if self.xss_var.get():
                args += ["--xss"]
            if self.log4j_var.get():
                args += ["--log4j"]
            if self.waf_var.get():
                args += ["--waf-bypass"]
            if self.http_var.get():
                args += ["--http-inspector"]
            if self.oob_var.get():
                args += ["--oob-attacks", "--oob-callback", self.oob_callback_var.get()]
        self.log.delete("1.0", "end")
        t = threading.Thread(target=self.run_proc, args=(args,))
        t.daemon = True
        t.start()

    def run_proc(self, args):
        try:
            proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=os.path.dirname(__file__))
            for line in proc.stdout:
                self.log.insert("end", line)
                self.log.see("end")
            proc.wait()
            self.log.insert("end", f"\nانتهى التنفيذ برمز: {proc.returncode}\n")
        except Exception as e:
            self.log.insert("end", f"\nخطأ: {e}\n")

def main():
    root = tk.Tk()
    app = DrSayerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()