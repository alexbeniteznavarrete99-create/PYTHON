import tkinter as tk
from tkinter import messagebox

def saludar():
    nombre = entry_nombre.get()
    if nombre == "":
        messagebox.showwarning("Aviso", "Ingresa tu nombre")
    else:
        messagebox.showinfo("Saludo", f"Hola, Bienvenido a la clase de Programación")

ventana = tk.Tk()
ventana.title("Saludo")
ventana.geometry("300x150")

tk.Label(ventana, text="Ingresa tu nombre: ").pack(pady=5)

entry_nombre = tk. Entry(ventana)
entry_nombre.pack(pady=5)

tk.Button(ventana, text="Saludar", command=saludar).pack(pady=10)

ventana.mainloop()