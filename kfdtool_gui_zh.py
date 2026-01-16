import serial
import serial.tools.list_ports
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import os
import json
from typing import Optional, Tuple, Callable

# ===== 协议常量（保持不变）=====
SOM_EOM = 0x61
ESC = 0x63
SOM_EOM_PLACEHOLDER = 0x62
ESC_PLACEHOLDER = 0x64

CMD_READ = 0x11
CMD_WRITE_INFO = 0x12

READ_AP_VER = 0x01
READ_FW_VER = 0x02
READ_UNIQUE_ID = 0x03
READ_MODEL_ID = 0x04
READ_HW_REV = 0x05
READ_SER_NUM = 0x06

WRITE_MDL_REV = 0x01
WRITE_SER = 0x02

CMD_PING = 0x15
RSP_PING = 0x25

CMD_REBOOT = 0x14
RSP_REBOOT = 0x24

CMD_ENTER_BSL = 0x13
RSP_ENTER_BSL = 0x23

ERR_MAP = {
    0x00: "其他错误",
    0x01: "命令长度无效",
    0x02: "命令操作码无效",
    0x03: "读取操作码无效",
    0x04: "读取失败",
    0x05: "写入操作码无效",
    0x06: "写入失败",
}

MODEL_MAP = {0: "未设置", 1: "KFD100", 2: "KFDAVR"}
MODEL_IDS = {"未设置": 0, "KFD100": 1, "KFDAVR": 2}


# ===== 底层通信类（增强日志支持）=====
class KFDTool:
    def __init__(self, port: str, baudrate=9600, logger: Callable[[str, bytes], None] = None):
        self.ser = serial.Serial(port, baudrate, timeout=0.1)
        self.ser.reset_input_buffer()
        self.ser.reset_output_buffer()
        self.logger = logger  # 日志回调函数

    def _frame_data(self, data: bytes) -> bytes:
        out = bytearray()
        out.append(SOM_EOM)
        for b in data:
            if b == SOM_EOM:
                out.extend([ESC, SOM_EOM_PLACEHOLDER])
            elif b == ESC:
                out.extend([ESC, ESC_PLACEHOLDER])
            else:
                out.append(b)
        out.append(SOM_EOM)
        return bytes(out)

    def _parse_frame(self, frame: bytes) -> Optional[bytes]:
        if len(frame) < 2 or frame[0] != SOM_EOM or frame[-1] != SOM_EOM:
            return None
        payload = bytearray()
        i = 1
        while i < len(frame) - 1:
            if frame[i] == ESC:
                i += 1
                if i >= len(frame) - 1:
                    return None
                if frame[i] == SOM_EOM_PLACEHOLDER:
                    payload.append(SOM_EOM)
                elif frame[i] == ESC_PLACEHOLDER:
                    payload.append(ESC)
                else:
                    return None
            else:
                payload.append(frame[i])
            i += 1
        return bytes(payload)

    def _receive_frame(self, timeout=2.0) -> Optional[bytes]:
        start_time = time.time()
        buffer = bytearray()
        in_frame = False
        max_bytes = 256

        while (time.time() - start_time < timeout) and (len(buffer) < max_bytes):
            if self.ser.in_waiting:
                b = self.ser.read(1)[0]
                if b == SOM_EOM:
                    if not in_frame:
                        buffer = bytearray([SOM_EOM])
                        in_frame = True
                    else:
                        buffer.append(SOM_EOM)
                        # === 记录接收到的原始帧 ===
                        if self.logger:
                            self.logger("RX", bytes(buffer))
                        # =========================
                        return self._parse_frame(bytes(buffer))
                elif in_frame:
                    buffer.append(b)
            time.sleep(0.001)
        return None

    def send_command(self, cmd: bytes) -> Optional[bytes]:
        frame = self._frame_data(cmd)
        if self.logger:
            self.logger("TX", frame)
        self.ser.write(frame)
        self.ser.flush()
        return self._receive_frame()

    # ... [以下所有方法保持不变，仅在实例化时传入 logger] ...
    def ping(self) -> Tuple[bool, int]:
        rsp = self.send_command(bytes([CMD_PING]))
        if rsp and len(rsp) >= 2 and rsp[0] == RSP_PING:
            return True, rsp[1]
        return False, 0

    def reboot(self) -> bool:
        try:
            rsp = self.send_command(bytes([CMD_REBOOT]))
            return rsp == bytes([RSP_REBOOT])
        except Exception:
            return False

    def enter_bsl(self) -> bool:
        try:
            rsp = self.send_command(bytes([CMD_ENTER_BSL]))
            return rsp == bytes([RSP_ENTER_BSL])
        except Exception:
            return False

    def read_ap_version(self) -> str:
        rsp = self.send_command(bytes([CMD_READ, READ_AP_VER]))
        if rsp and len(rsp) >= 5 and rsp[0] == 0x21 and rsp[1] == READ_AP_VER:
            return f"{rsp[2]}.{rsp[3]}.{rsp[4]}"
        raise RuntimeError("读取适配器协议版本失败")

    def read_fw_version(self) -> str:
        rsp = self.send_command(bytes([CMD_READ, READ_FW_VER]))
        if rsp and len(rsp) >= 5 and rsp[0] == 0x21 and rsp[1] == READ_FW_VER:
            return f"{rsp[2]}.{rsp[3]}.{rsp[4]}"
        raise RuntimeError("读取固件版本失败")

    def read_unique_id(self) -> str:
        rsp = self.send_command(bytes([CMD_READ, READ_UNIQUE_ID]))
        if not rsp or len(rsp) < 3 or rsp[0] != 0x21 or rsp[1] != READ_UNIQUE_ID:
            raise RuntimeError("读取唯一ID失败")
        data_len = rsp[2]
        if len(rsp) < 3 + data_len:
            raise RuntimeError("唯一ID数据不完整")
        return rsp[3:3 + data_len].hex().upper()

    def read_model_id(self) -> int:
        rsp = self.send_command(bytes([CMD_READ, READ_MODEL_ID]))
        if rsp and len(rsp) >= 3 and rsp[0] == 0x21 and rsp[1] == READ_MODEL_ID:
            return rsp[2]
        raise RuntimeError("读取型号ID失败")

    def read_hw_rev(self) -> Tuple[int, int]:
        rsp = self.send_command(bytes([CMD_READ, READ_HW_REV]))
        if rsp and len(rsp) >= 4 and rsp[0] == 0x21 and rsp[1] == READ_HW_REV:
            return rsp[2], rsp[3]
        raise RuntimeError("读取硬件版本失败")

    def read_serial_number(self) -> str:
        rsp = self.send_command(bytes([CMD_READ, READ_SER_NUM]))
        if not rsp or len(rsp) < 3 or rsp[0] != 0x21 or rsp[1] != READ_SER_NUM:
            raise RuntimeError("读取序列号失败")
        ser_len = rsp[2]
        if len(rsp) < 3 + ser_len:
            raise RuntimeError("序列号数据不完整")
        raw = rsp[3:3 + ser_len]
        try:
            return raw.decode('ascii')
        except UnicodeDecodeError:
            return f"[非ASCII] {raw.hex().upper()}"

    def write_model_hwrev(self, model_id: int, hw_maj: int, hw_min: int):
        cmd = bytes([CMD_WRITE_INFO, WRITE_MDL_REV, model_id, hw_maj, hw_min])
        rsp = self.send_command(cmd)
        if rsp and rsp[0] == 0x22:
            return True
        elif rsp and rsp[0] == 0x20:
            err = ERR_MAP.get(rsp[1], "未知错误")
            raise RuntimeError(f"写入失败: {err}")
        raise RuntimeError("无响应")

    def write_serial_number(self, serial_str: str):
        if len(serial_str) != 6:
            raise ValueError("序列号必须为6个字符")
        for c in serial_str:
            if not (32 <= ord(c) <= 126):
                raise ValueError("仅支持可打印ASCII字符")
        cmd = bytes([CMD_WRITE_INFO, WRITE_SER] + [ord(c) for c in serial_str])
        rsp = self.send_command(cmd)
        if rsp and rsp[0] == 0x22:
            return True
        elif rsp and rsp[0] == 0x20:
            err = ERR_MAP.get(rsp[1], "未知错误")
            raise RuntimeError(f"写入失败: {err}")
        raise RuntimeError("无响应")

    def close(self):
        if self.ser and self.ser.is_open:
            self.ser.close()


# ===== NanoKFD 配置工具 v1.1（带运行日志）=====
class NanoKFDConfigGUI:
    CONFIG_FILE = "nanokfd_config.json"

    def __init__(self, root):
        self.root = root
        self.root.title("NanoKFD 配置工具 v1.1")
        self.root.geometry("560x580")  # 高度增加以容纳日志区
        self.root.resizable(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.device_info = {}
        self.is_kfd_confirmed = False
        self.last_success_port = None

        self._load_config()
        self.create_widgets()
        self.refresh_ports()

        if self.last_success_port:
            self.port_var.set(self.last_success_port)
            self._try_quick_verify(self.last_success_port)

    def _load_config(self):
        try:
            if os.path.exists(self.CONFIG_FILE):
                with open(self.CONFIG_FILE, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    self.last_success_port = config.get("last_port")
        except Exception:
            self.last_success_port = None

    def _save_config(self, port: str):
        try:
            with open(self.CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump({"last_port": port}, f)
            self.last_success_port = port
        except Exception:
            pass

    def log_hex(self, direction: str, data: bytes):
        """记录十六进制日志"""
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        hex_str = ' '.join(f'{b:02X}' for b in data)
        log_line = f"[{timestamp}] {direction}: {hex_str}\n"
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, log_line)
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')

    def _try_quick_verify(self, port: str):
        def task():
            try:
                tool = KFDTool(port, logger=self.log_hex)  # ← 传入 logger
                is_kfd, _ = tool.ping()
                tool.close()
                if is_kfd:
                    self.is_kfd_confirmed = True
                    self.root.after(0, lambda: self.show_info("🔍 正在读取 NanoKFD 设备信息...\n请稍候（约1-2秒）"))
                    self.root.after(0, self.read_device)
                else:
                    self.root.after(0, lambda: self.show_info("上次设备未连接或不可用。"))
            except Exception:
                self.root.after(0, lambda: self.show_info("上次设备未连接或不可用。"))

        threading.Thread(target=task, daemon=True).start()

    def create_widgets(self):
        port_frame = ttk.Frame(self.root)
        port_frame.pack(pady=8, padx=10, fill='x')

        ttk.Label(port_frame, text="串口:").pack(side='left')
        self.port_var = tk.StringVar()
        self.port_combo = ttk.Combobox(port_frame, textvariable=self.port_var, width=18, state='readonly')
        self.port_combo.pack(side='left', padx=5)
        self.refresh_btn = ttk.Button(port_frame, text="刷新", command=self.refresh_ports, width=6)
        self.refresh_btn.pack(side='left', padx=2)
        self.auto_btn = ttk.Button(port_frame, text="自动检测", command=self.auto_detect, width=8)
        self.auto_btn.pack(side='left', padx=2)

        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(pady=6)

        self.read_btn = ttk.Button(btn_frame, text="读取设备信息", command=self.read_device, width=12)
        self.read_btn.pack(side='left', padx=3)

        self.write_sn_btn = ttk.Button(btn_frame, text="写入序列号", command=self.open_write_sn_window, width=12)
        self.write_sn_btn.pack(side='left', padx=3)

        self.write_model_btn = ttk.Button(btn_frame, text="写入型号与硬件版本", command=self.open_write_model_window, width=18)
        self.write_model_btn.pack(side='left', padx=3)

        self.reboot_btn = ttk.Button(btn_frame, text="重启设备", command=self.reboot_device, width=10)
        self.reboot_btn.pack(side='left', padx=3)

        self.bsl_btn = ttk.Button(btn_frame, text="进入BSL模式", command=self.enter_bsl_mode, width=12)
        self.bsl_btn.pack(side='left', padx=3)

        info_frame = ttk.LabelFrame(self.root, text="设备信息")
        info_frame.pack(pady=10, padx=10, fill='both', expand=True)

        self.info_text = scrolledtext.ScrolledText(
            info_frame, wrap=tk.WORD, height=10,
            state='disabled', font=('Consolas', 10)
        )
        self.info_text.pack(fill='both', expand=True, padx=5, pady=5)

        # ===== 新增：运行日志区域 =====
        log_frame = ttk.LabelFrame(self.root, text="运行日志")  # ← 已修改此处
        log_frame.pack(pady=5, padx=10, fill='both', expand=False, side='bottom')
        self.log_text = scrolledtext.ScrolledText(
            log_frame, wrap=tk.NONE, height=6,
            state='disabled', font=('Consolas', 9)
        )
        self.log_text.pack(fill='both', expand=True, padx=5, pady=5)

        bottom_frame = ttk.Frame(self.root)
        bottom_frame.pack(side='bottom', fill='x', padx=10, pady=5)
        ttk.Button(bottom_frame, text="关于", command=self.show_about, width=8).pack(side='right')

    def on_closing(self):
        self.root.destroy()

    def refresh_ports(self):
        ports = [p.device for p in serial.tools.list_ports.comports()]
        if not ports:
            ports = ["无"]
        self.port_combo['values'] = ports
        current = self.port_var.get()
        if current not in ports and ports[0] != "无":
            self.port_var.set(ports[0])
        elif not current:
            self.port_var.set(ports[0])

    def show_info(self, text):
        self.info_text.config(state='normal')
        self.info_text.delete(1.0, tk.END)
        self.info_text.insert(tk.END, text)
        self.info_text.config(state='disabled')

    def _ensure_kfd_confirmed(self) -> bool:
        if not self.is_kfd_confirmed:
            messagebox.showwarning("操作受限", "请先点击“自动检测”按钮，\n确认已连接 NanoKFD 设备后再操作。")
            return False
        return True

    def auto_detect(self):
        self.show_info("正在自动检测 NanoKFD 设备...\n")
        ports = [p.device for p in serial.tools.list_ports.comports()]
        found = False
        for port in ports:
            try:
                tool = KFDTool(port, logger=self.log_hex)  # ← 传入 logger
                is_kfd, _ = tool.ping()
                tool.close()
                if is_kfd:
                    self.port_var.set(port)
                    self.is_kfd_confirmed = True
                    self._save_config(port)
                    self.show_info("🔍 正在读取 NanoKFD 设备信息...\n请稍候（约1-2秒）")
                    self.read_device()
                    found = True
                    break
            except Exception:
                continue
        if not found:
            self.is_kfd_confirmed = False
            msg = "❌ 未检测到 NanoKFD 设备。\n请确保设备已连接并上电。"
            self.show_info(msg)
            messagebox.showinfo("自动检测", "未找到 NanoKFD 设备。")

    def _disable_buttons(self):
        for btn in [self.read_btn, self.write_sn_btn, self.write_model_btn, self.reboot_btn, self.bsl_btn]:
            btn.config(state='disabled')
        self.refresh_btn.config(state='disabled')
        self.auto_btn.config(state='disabled')

    def _enable_buttons(self):
        for btn in [self.read_btn, self.write_sn_btn, self.write_model_btn, self.reboot_btn, self.bsl_btn]:
            btn.config(state='normal')
        self.refresh_btn.config(state='normal')
        self.auto_btn.config(state='normal')

    def read_device(self):
        if not self._ensure_kfd_confirmed():
            return
        port = self.port_var.get()
        if port == "无":
            messagebox.showerror("错误", "未选择串口。")
            self.show_info("⚠️ 未选择串口。")
            return

        self._disable_buttons()
        self.show_info("🔍 正在读取 NanoKFD 设备信息...\n请稍候（约1-2秒）。")

        def task():
            try:
                tool = KFDTool(port, logger=self.log_hex)  # ← 传入 logger
                is_kfd, dev_type = tool.ping()
                if not is_kfd:
                    tool.close()
                    raise RuntimeError("设备无响应或非 NanoKFD 设备（自检失败）")

                info = {
                    'ap': tool.read_ap_version(),
                    'fw': tool.read_fw_version(),
                    'uid': tool.read_unique_id(),
                    'mid': tool.read_model_id(),
                    'hw': tool.read_hw_rev(),
                    'sn': tool.read_serial_number()
                }
                tool.close()

                model_name = MODEL_MAP.get(info['mid'], f"未知 (ID={info['mid']})")
                hw_str = f"{info['hw'][0]}.{info['hw'][1]}"

                display = (
                    f"适配器协议版本: {info['ap']}\n"
                    f"固件版本      : {info['fw']}\n"
                    f"唯一ID        : {info['uid']}\n"
                    f"型号          : {model_name} (ID={info['mid']})\n"
                    f"硬件版本      : {hw_str}\n"
                    f"序列号        : {info['sn']}"
                )
                self.device_info = info
                self.root.after(0, lambda: self.show_info(display))
            except serial.SerialException as e:
                error_msg = f"❌ 串口错误 ({port}):\n{str(e)}"
                self.root.after(0, lambda: self.show_info(error_msg))
                self.root.after(0, lambda: messagebox.showerror("串口错误", f"无法访问串口 {port}:\n{e}"))
            except Exception as e:
                error_msg = f"❌ 从 {port} 读取失败:\n{str(e)}"
                self.root.after(0, lambda: self.show_info(error_msg))
                self.root.after(0, lambda: messagebox.showerror("读取错误", str(e)))
            finally:
                self.root.after(0, self._enable_buttons)

        threading.Thread(target=task, daemon=True).start()

    def open_write_sn_window(self):
        if not self._ensure_kfd_confirmed():
            return
        if not self.device_info:
            messagebox.showwarning("警告", "请先读取设备信息。")
            return

        win = tk.Toplevel(self.root)
        win.title("写入序列号")
        win.geometry("300x160")
        win.resizable(False, False)
        win.grab_set()

        ttk.Label(win, text="当前序列号:").pack(pady=(10, 0))
        ttk.Label(win, text=self.device_info['sn'], font=('Courier', 10)).pack()
        ttk.Label(win, text="新序列号（6个可打印ASCII字符）:").pack(pady=(10, 5))
        sn_var = tk.StringVar()
        sn_entry = ttk.Entry(win, textvariable=sn_var, width=12, justify='center')
        sn_entry.pack()
        sn_entry.focus()

        def confirm():
            new_sn = sn_var.get()
            if len(new_sn) != 6:
                messagebox.showerror("错误", "必须为6个字符。", parent=win)
                return
            for c in new_sn:
                if not (32 <= ord(c) <= 126):
                    messagebox.showerror("错误", "仅支持可打印ASCII字符（空格~~）。", parent=win)
                    return

            if messagebox.askyesno("确认", f"将序列号从:\n'{self.device_info['sn']}'\n\n改为:\n'{new_sn}'\n\n是否继续？", parent=win):
                self.write_serial_number(new_sn)
                win.destroy()

        ttk.Button(win, text="写入", command=confirm).pack(pady=10)

    def write_serial_number(self, new_sn):
        port = self.port_var.get()

        def task():
            try:
                tool = KFDTool(port, logger=self.log_hex)  # ← 传入 logger
                tool.write_serial_number(new_sn)
                tool.close()
                self.root.after(0, lambda: messagebox.showinfo("成功", "序列号已写入！"))
                self.root.after(0, self.read_device)
            except serial.SerialException as e:
                self.root.after(0, lambda: messagebox.showerror("串口错误", f"无法访问串口 {port}:\n{e}"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("写入错误", str(e)))

        threading.Thread(target=task, daemon=True).start()

    def open_write_model_window(self):
        if not self._ensure_kfd_confirmed():
            return
        if not self.device_info:
            messagebox.showwarning("警告", "请先读取设备信息。")
            return

        win = tk.Toplevel(self.root)
        win.title("写入型号与硬件版本")
        win.geometry("320x210")
        win.resizable(False, False)
        win.grab_set()

        current_mid = self.device_info['mid']
        current_hw = self.device_info['hw']
        current_model = MODEL_MAP.get(current_mid, f"自定义 ({current_mid})")

        ttk.Label(win, text=f"当前型号: {current_model} (ID={current_mid})").pack(pady=(10, 0))
        ttk.Label(win, text=f"当前硬件版本: {current_hw[0]}.{current_hw[1]}").pack()

        ttk.Label(win, text="新型号:").pack(pady=(10, 0))
        model_var = tk.StringVar(value=current_model)
        model_combo = ttk.Combobox(win, textvariable=model_var, values=list(MODEL_MAP.values()), state="readonly", width=14)
        model_combo.pack()

        ttk.Label(win, text="新硬件版本（格式: X.Y，如 2.0）:").pack(pady=(8, 0))
        hw_var = tk.StringVar(value=f"{current_hw[0]}.{current_hw[1]}")
        hw_entry = ttk.Entry(win, textvariable=hw_var, width=12)
        hw_entry.pack()

        def confirm():
            model_name = model_var.get()
            if model_name not in MODEL_IDS:
                messagebox.showerror("错误", "无效的型号。", parent=win)
                return
            model_id = MODEL_IDS[model_name]

            hw_str = hw_var.get().strip()
            try:
                parts = hw_str.split('.')
                hw_maj = int(parts[0])
                hw_min = int(parts[1]) if len(parts) > 1 else 0
                if hw_maj < 0 or hw_min < 0:
                    raise ValueError
            except Exception:
                messagebox.showerror("错误", "硬件版本格式无效（应为非负整数，如 1.0）。", parent=win)
                return

            msg = (
                f"将从:\n"
                f"  {current_model} (ID={current_mid}), 硬件 {current_hw[0]}.{current_hw[1]}\n\n"
                f"改为:\n"
                f"  {model_name} (ID={model_id}), 硬件 {hw_maj}.{hw_min}\n\n"
                f"此操作为原子写入，不可逆。是否继续？"
            )
            if messagebox.askyesno("确认原子写入", msg, parent=win):
                self.write_model_hwrev(model_id, hw_maj, hw_min)
                win.destroy()

        ttk.Button(win, text="写入", command=confirm).pack(pady=12)

    def write_model_hwrev(self, model_id, hw_maj, hw_min):
        port = self.port_var.get()

        def task():
            try:
                tool = KFDTool(port, logger=self.log_hex)  # ← 传入 logger
                tool.write_model_hwrev(model_id, hw_maj, hw_min)
                tool.close()
                self.root.after(0, lambda: messagebox.showinfo("成功", "型号与硬件版本已写入！"))
                self.root.after(0, self.read_device)
            except serial.SerialException as e:
                self.root.after(0, lambda: messagebox.showerror("串口错误", f"无法访问串口 {port}:\n{e}"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("写入错误", str(e)))

        threading.Thread(target=task, daemon=True).start()

    def reboot_device(self):
        if not self._ensure_kfd_confirmed():
            return
        port = self.port_var.get()
        if port == "无":
            messagebox.showerror("错误", "未选择串口。")
            return

        def task():
            try:
                tool = KFDTool(port, logger=self.log_hex)  # ← 传入 logger
                success = tool.reboot()
                tool.close()
                if success:
                    self.root.after(0, lambda: messagebox.showinfo("成功", "✅ 收到重启确认，设备正在重启！"))
                else:
                    self.root.after(0, lambda: messagebox.showerror("失败", "❌ 未收到设备确认，重启可能未生效。"))
            except serial.SerialException as e:
                self.root.after(0, lambda: messagebox.showerror("串口错误", f"无法访问串口 {port}:\n{e}"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("错误", f"发送重启命令失败:\n{e}"))

        threading.Thread(target=task, daemon=True).start()

    def enter_bsl_mode(self):
        if not self._ensure_kfd_confirmed():
            return
        port = self.port_var.get()
        if port == "无":
            messagebox.showerror("错误", "未选择串口。")
            return

        if not messagebox.askyesno(
            "确认进入 BSL",
            "进入 BSL 模式后，设备将停止正常工作，\n"
            "并等待固件升级（如使用 K-Flash、UART ISP 等工具）。\n\n"
            "此操作不可逆，直到新固件烧录完成。\n\n是否继续？",
            parent=self.root
        ):
            return

        def task():
            try:
                tool = KFDTool(port, logger=self.log_hex)  # ← 传入 logger
                success = tool.enter_bsl()
                tool.close()
                if success:
                    self.device_info.clear()
                    self.is_kfd_confirmed = False  # ← 关键：重置状态！
                    self.root.after(0, lambda: self.show_info("✅ 设备已进入 BSL 模式（收到确认）。"))
                    self.root.after(0, lambda: messagebox.showinfo(
                        "BSL 模式",
                        "✅ 收到 BSL 确认，设备已进入 Bootloader 模式！\n\n"
                        "请立即使用 K-Flash 等工具进行固件烧录。"
                    ))
                else:
                    self.root.after(0, lambda: messagebox.showerror("失败", "❌ 未收到 BSL 确认，请检查设备是否支持或已连接。"))
            except serial.SerialException as e:
                self.root.after(0, lambda: messagebox.showerror("串口错误", f"无法访问串口 {port}:\n{e}"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("错误", f"发送 BSL 命令失败:\n{e}"))

        threading.Thread(target=task, daemon=True).start()

    def show_about(self):
        about_info = (
            "NanoKFD 配置工具 v1.1（带运行日志）\n\n"
            "功能：读取/写入 NanoKFD 设备的序列号、\n"
            "      型号、硬件版本等配置信息。\n\n"
            "© 2026 BG4TGO\n"
            "作者：Tom\n"
            "邮箱：bg4tgo@126.com\n"
            "项目地址：https://8.159.133.139\n\n"
            "本软件遵循 MIT 开源许可证。"
        )
        messagebox.showinfo("关于 NanoKFD 配置工具", about_info)


# ===== 启动入口 =====
if __name__ == "__main__":
    root = tk.Tk()
    app = NanoKFDConfigGUI(root)
    root.mainloop()
