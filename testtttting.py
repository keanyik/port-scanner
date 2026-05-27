import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import re

class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("精准端口分析器 (按需解析版)")
        self.root.geometry("600x650")
        
        self.is_scanning = False
        self.free_ports = []
        self.occupied_ports_info = [] 
        
        self.create_widgets()

    def create_widgets(self):
        input_frame = ttk.LabelFrame(self.root, text=" 扫描设置 ", padding=10)
        input_frame.pack(fill="x", padx=15, pady=10)

        ttk.Label(input_frame, text="起始端口:").grid(row=0, column=0, sticky="w", pady=5)
        self.start_entry = ttk.Entry(input_frame, width=8)
        self.start_entry.insert(0, "1024")
        self.start_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="结束端口:").grid(row=0, column=2, sticky="w", pady=5)
        self.end_entry = ttk.Entry(input_frame, width=8)
        self.end_entry.insert(0, "2000") # 默认范围缩小，方便体验精准解析
        self.end_entry.grid(row=0, column=3, padx=5, pady=5)

        self.scan_btn = ttk.Button(input_frame, text="一键分析系统", command=self.start_fast_scan)
        self.scan_btn.grid(row=0, column=4, padx=10, pady=5)

        self.status_label = ttk.Label(self.root, text="就绪。点击开始精准分析。", foreground="gray")
        self.status_label.pack(anchor="w", padx=15, pady=2)

        self.view_mode = tk.StringVar(value="free")
        mode_frame = ttk.Frame(self.root)
        mode_frame.pack(fill="x", padx=15, pady=5)
        
        self.radio_free = ttk.Radiobutton(mode_frame, text="显示【未占用】的空闲端口", variable=self.view_mode, value="free", command=self.refresh_display)
        self.radio_free.pack(side="left", padx=10)
        
        self.radio_occupied = ttk.Radiobutton(mode_frame, text="显示【已被占用】的端口 (按需解析程序名)", variable=self.view_mode, value="occupied", command=self.refresh_display)
        self.radio_occupied.pack(side="left", padx=10)

        result_frame = ttk.LabelFrame(self.root, text=" 数据显示区域 ", padding=10)
        result_frame.pack(fill="both", expand=True, padx=15, pady=5)

        self.result_box = tk.Text(result_frame, wrap="word", width=60, height=20, font=("Consolas", 10))
        scrollbar = ttk.Scrollbar(result_frame, command=self.result_box.yview)
        self.result_box.configure(yscrollcommand=scrollbar.set)
        
        self.result_box.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def get_program_name_by_pid(self, pid):
        """核心：只针对被占用的 PID，精准调用系统命令查询程序名"""
        try:
            # 使用 wmic 精确查询单条 PID，避免全进程扫描
            cmd = f"wmic process where processid={pid} get caption"
            output = subprocess.check_output(cmd, shell=True, text=True, errors='ignore')
            lines = [line.strip() for line in output.splitlines() if line.strip()]
            if len(lines) > 1:
                return lines[1] # 第二行就是程序文件名 (例如 svchost.exe)
        except Exception:
            pass
        return "Unknown"

    def start_fast_scan(self):
        if self.is_scanning:
            return

        try:
            start = int(self.start_entry.get())
            end = int(self.end_entry.get())
            if not (0 <= start <= 65535 and 0 <= end <= 65535) or start > end:
                raise ValueError
        except ValueError:
            messagebox.showerror("错误", "请输入有效的端口范围 (0-65535)")
            return

        self.is_scanning = True
        self.scan_btn.config(state="disabled")
        self.status_label.config(text="正在获取端口连接快照...", foreground="blue")
        self.result_box.delete("1.0", tk.END)

        threading.Thread(target=self.run_fast_scan, args=(start, end), daemon=True).start()

    def run_fast_scan(self, start, end):
        occupied_map = {}
        
        try:
            # 1. 第一步：先找出指定范围内哪些端口被占用了
            output = subprocess.check_output("netstat -ano", shell=True, text=True, errors='ignore')
            pattern = re.compile(r'(?:TCP|UDP)\s+(?:\[[0-9a-fA-F:]+\]|(?:\d{1,3}\.){3}\d{1,3}):(\d+)\s+.*\s+(\d+)\s*$')
            
            for line in output.splitlines():
                match = pattern.search(line.strip())
                if match:
                    port_num = int(match.group(1))
                    pid_num = match.group(2)
                    if start <= port_num <= end:
                        if port_num not in occupied_map:
                            occupied_map[port_num] = set()
                        occupied_map[port_num].add(pid_num)
                        
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("错误", f"无法读取网络状态: {e}"))
            self.root.after(0, self.scan_complete, 0)
            return

        # 2. 第二步：精准打击！只给“已被占用”的端口解析程序名
        self.occupied_ports_info = []
        total_occupied = len(occupied_map)
        
        for idx, p in enumerate(sorted(occupied_map.keys())):
            # 更新状态栏提示进度
            self.root.after(0, lambda i=idx+1: self.status_label.config(
                text=f"正在精准解析被占用的程序名... ({i}/{total_occupied})", foreground="blue"
            ))
            
            pids = occupied_map[p]
            names = []
            for pid in pids:
                # 只有被占用了，才现场查名字
                prog_name = self.get_program_name_by_pid(pid)
                names.append(prog_name)
            
            pids_str = "/".join(pids)
            names_str = "/".join(set(names))
            self.occupied_ports_info.append(f"端口 {p:<6} [PID: {pids_str:<6}] -> 进程: {names_str}")

        # 3. 计算差集得出空闲端口
        all_requested_ports = set(range(start, end + 1))
        occupied_ports_set = set(occupied_map.keys())
        free_ports_set = all_requested_ports - occupied_ports_set
        self.free_ports = sorted(list(free_ports_set))
        
        self.root.after(0, self.scan_complete, total_occupied)

    def scan_complete(self, occupied_count):
        self.is_scanning = False
        self.scan_btn.config(state="normal")
        self.status_label.config(text=f"分析完成！当前范围内有 {occupied_count} 个端口被占用。", foreground="green")
        self.refresh_display()

    def refresh_display(self):
        if not self.free_ports and not self.occupied_ports_info:
            return
            
        self.result_box.delete("1.0", tk.END)
        mode = self.view_mode.get()
        
        if mode == "free":
            if self.free_ports:
                result_str = ", ".join(map(str, self.free_ports))
                self.result_box.insert(tk.END, f"--- 【未占用】的空闲端口 (共 {len(self.free_ports)} 个) ---\n\n" + result_str)
            else:
                self.result_box.insert(tk.END, "该范围内没有空闲端口。")
        else:
            if self.occupied_ports_info:
                result_str = "\n".join(self.occupied_ports_info)
                self.result_box.insert(tk.END, f"--- 【已被占用】的端口及关联程序 (共 {len(self.occupied_ports_info)} 个) ---\n\n" + result_str)
            else:
                self.result_box.insert(tk.END, "该范围内没有被占用的端口。")

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()
