import tkinter as tk
def sumar():
    num1=int(entry1.get())
    num2=int(entry2.get())
    resultado = num1 + num2
    result.config(text=f"La suma es {resultado}")

def restar():
    num1=int(entry1.get())
    num2=int(entry2.get())
    resultado = num1 - num2
    result.config(text=f"La resta es {resultado}")

def multiplicar():
    num1=int(entry1.get())
    num2=int(entry2.get())
    resultado = num1 * num2
    result.config(text=f"La multiplicacion es {resultado}")

def dividir():
    num1=int(entry1.get())
    num2=int(entry2.get())
    resultado = num1 / num2
    result.config(text=f"La división es {resultado}")

ventana = tk.Tk()
ventana.geometry("300x400")
ventana.title("Calculadora")

frame = tk.Frame(ventana,bg="yellow")
frame.pack(fill="both" ,expand="true")

label1 =tk.Label(frame, text="Ingrese un numero",font=("Arial",15,"bold"), bg="yellow")
label1.pack()

entry1 = tk.Entry(frame)
entry1.pack()

label2 =tk.Label(frame, text="Ingrese otro numero",font=("Arial",20,"bold"), bg="yellow")
label2.pack()

entry2 = tk.Entry(frame)
entry2.pack()

button = tk.Button(frame, text="sumar", command=sumar)
button.pack()

button = tk.Button(frame, text="restar", command=restar)
button.pack()

button = tk.Button(frame, text="multiplicar", command=multiplicar)
button.pack()

button = tk.Button(frame, text="dividir", command=dividir)
button.pack()

result = tk. Label(frame,text="",font=("Arial",20,"bold"),bg="yellow")
result.pack()

ventana.mainloop()