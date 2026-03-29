import tkinter as tk
def saludar():
    nombre=int(entry.get())
    print("Hola", nombre)

ventana = tk.Tk()
ventana.geometry("300x400")
ventana.title("saludo")

frame = tk.Frame(ventana,bg="yellow")
frame.pack(fill="both" ,expand="true")

label =tk.Label(ventana, text="Ingrese su nombre")
label.pack()

entry = tk.Entry(ventana)
entry.pack()

label =tk.Label(ventana, text="Ingrese su edad")
label.pack()

entry = tk.Entry(ventana)
entry.pack()

button = tk.Button(ventana, text="saludar", command=saludar)
button.pack()
ventana.mainloop()