lista=[]

cantidad = int(input("ingrese la cantidad de notas: "))
for i in range(notas):
    numero = int(input(f"ingrese un numero en la posicion {i} : "))
    lista.append(numero)
print(lista)