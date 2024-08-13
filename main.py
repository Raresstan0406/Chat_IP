import tkinter as tk
from scapy.all import *
from tkinter import ttk
import threading
import time
from tkinter import messagebox, OptionMenu, StringVar


def create_and_send_packet():
    payload = entry_mesaj.get()
    ip_packet = IP(dst=entry_ipdest.get()) / Raw(load=payload)
    if entry_parola.get() != "Telacad":
        messagebox.showinfo("!!!", "Parola nu este corecta")
    else:
        send(ip_packet)
        update_chat(f"Sent: {payload}")


def decode_payload(pkt):
    if pkt.haslayer(IP):
        ip = pkt.getlayer(IP)
        if ip.src == entry_ipdest.get():
            if pkt.haslayer(Raw):
                raw_data = pkt.getlayer(Raw).load
                decoded = raw_data.decode('utf-8')
                try:
                    update_chat(f"Recieved: {decoded}")
                except UnicodeDecodeError:
                    pass
                for op in options:
                    if decoded == op:
                        messagebox.showinfo("!!!", "     ||   ||\n \_______/")


def threading_sniff():
    if entry_parola.get() != "Telacad":
        messagebox.showinfo("!!!", "Parola nu este corecta")
    else:
        threading.Thread(target=start_sniffing, daemon=True).start()


def start_sniffing():
    time.sleep(0.1)
    sniff(filter=f"ip dst {entry_ipsniff.get()}", prn=decode_payload)


def update_chat(mesaj):
    # username = entry_user.get()
    chat_text.configure(state='normal')
    chat_text.insert(tk.END, f"{mesaj}\n")
    chat_text.configure(state='disabled')
    chat_text.see(tk.END)


def alarma():
    if entry_parola.get() != "Telacad":
        messagebox.showinfo("!!!", "Parola nu este corecta")
    else:
        ip_packet = IP(dst=entry_ipdest.get()) / Raw(load=selected_value.get())
        send(ip_packet)
       # update_chat(f"Sent: {selected_value.get()}")

if __name__=="__main__":
    root = tk.Tk()
    root.title("Chat")
    root.geometry("700x360")
    root.resizable(True, True)
    label_user = ttk.Label(root, text='User:')
    label_user.grid(row=0, column=0, sticky="w")
    entry_user = ttk.Entry(root)
    entry_user.grid(row=0, column=0, padx=100, sticky="ew")
    label_parola = ttk.Label(root, text="Parola:")
    label_parola.grid(row=1, column=0, sticky="w")
    entry_parola = ttk.Entry(root)
    entry_parola.grid(row=1, column=0, padx=100, sticky="ew")
    chat_frame = ttk.LabelFrame(root, text="Chat")
    chat_frame.grid(row=2, column=0, columnspan=1, sticky="ew")
    chat_text = tk.Text(chat_frame, height=10, state='disabled')
    chat_text.pack(fill='both', expand=True)

    label_ipdest = ttk.Label(root, text='IP destinatie:')
    label_ipdest.grid(row=3, column=0, sticky="ew")
    entry_ipdest = ttk.Entry(root)
    entry_ipdest.grid(row=3, column=0, padx=100, sticky="ew")
    label_mesaj = ttk.Label(root, text='Mesaj: ')
    label_mesaj.grid(row=4, column=0, sticky="ew")
    entry_mesaj = ttk.Entry(root)
    entry_mesaj.grid(row=4, column=0, padx=100, sticky="ew")
    label_ipsniff = ttk.Label(root, text=' IP sniff:')
    label_ipsniff.grid(row=5, column=0, sticky="ew")
    entry_ipsniff = ttk.Entry(root)
    entry_ipsniff.grid(row=5, column=0, padx=100, sticky="ew")
    selected_value = StringVar(root)
    selected_value.set("Alege alarma:")
    options = ["X864", "BD89", "AC66", "Kz50"]
    choice_bar = OptionMenu(root, selected_value, *options)
    choice_bar.grid(row=6, padx=20, sticky="ew")
    button_alarma = ttk.Button(root, text="Trimite alarma", command=alarma)
    button_alarma.grid(row=7, column=0, sticky="w")
    button_sniff = ttk.Button(root, text="IP sniff", command=threading_sniff)
    button_sniff.grid(row=7, column=0, padx=150, sticky="w")
    button_trimite = ttk.Button(root, text='Trimite', command=create_and_send_packet)
    button_trimite.grid(row=7, column=0, padx=300, sticky="w")
    root.mainloop()

