#Calculadora de IMC con Tkinter
#Desarrolla una aplicación de escritorio en Python que calcule el 
# Índice de Masa Corporal (IMC) de una persona, 
# utilizando la librería tkinter para la interfaz gráfica.

import tkinter as tk
from tkinter import messagebox

def calcular_imc():
    try:
        peso = float(entry_peso.get())
        altura = float(entry_altura.get())

        if altura <= 0:
            raise ValueError
        imc = peso / (altura ** 2)

        if imc < 18.5:
            estado = "Bajo peso"
        elif imc < 24.9:
            estado = "Normal"
        elif imc < 29.9:
            estado = "Sobrepeso"
        else: 
            estado = "Obesidad"
        
        resultado.set(f"IMC: {imc:.2f} ({estado})")

    except:
        messagebox.showerror("Error", "Ingresa valores validos")

ventana = tk.Tk()
ventana.title("Calculadora IMC")
ventana.geometry("300x200")

resultado = tk.StringVar()

tk.Label(ventana, text="Peso (kg):").pack()
entry_peso = tk.Entry(ventana)
entry_peso.pack()

tk.Label(ventana, text="Altura (m):").pack()
entry_altura = tk.Entry(ventana)
entry_altura.pack()

tk.Button(ventana, text="Calcular IMC", command=calcular_imc).pack(pady=10)

tk.Label(ventana, textvariable=resultado, fg="blue").pack()

ventana.mainloop()