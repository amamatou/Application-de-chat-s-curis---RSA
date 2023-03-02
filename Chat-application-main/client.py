# On importe tous les modules requis
import socket
import threading
from tkinter import *
import pickle
import rsa
import binascii

# Saisie du nom du client
name=input("Entrez votre nom : ")

# Generation des paires de cles privees et publiques du client avec RSA
public, private = rsa.generate_keypair(1024)

# pickle.dumps() permet de sérialiser une hiérarchie d'objets, ici la cle publique
msg=pickle.dumps(public)
# cle publique du client
print(public[0])

def set_ip():
    # Recuperation de l'adresse ip et du port depuis la zone de texte
    ip = edit_text_ip.get()
    port = edit_text_port.get()

    # Definition du client et connexion au serveur:
    global client
    client = socket.socket()
    client.connect((ip, int(port)))

    # Destruction de l'input root ou racine d'entree
    input_root.destroy()

    # fin de input root:
    input_root.quit()

# fonction d'envoi de message
def send():
    # si la zone texte est non vide
    if str(edit_text.get()).strip() != "":
        # recuperation et convertion en octects du message
        message = str.encode(edit_text.get())
        #convertion en numb
        hex_data   = binascii.hexlify(message)
        plain_text = int(hex_data, 16)
        # chiffrement du texte brut(message en entier) avec la cle publique
        ctt=rsa.encrypt(plain_text,pkey)
        # envoi du message chiffré au server
        client.send(str(ctt).encode())
        # barre de défilement:
        listbox.insert(END, message)
        edit_text.delete(0, END)

# fonction de recuperation de message
def recv():
    while True:
        # reponse du server
        response_message =int(client.recv(1024).decode())
        print(response_message)
        # decryptage du msg avec la clé privée du client
        decrypted_msg = rsa.decrypt(response_message, private)
        # barre de défilement:
        listbox.insert(END, name1 +" : "+ str(decrypted_msg))
        edit_text.delete(0, END)


# Interface graphique client

# 1: Interface graphique de la racine d'entrée(input root)
input_root = Tk()
bgimage = PhotoImage(file ="images.png")
Label(input_root,image=bgimage).place(relwidth=1,relheight=1)
edit_text_ip = Entry()
edit_text_port = Entry()
ip_label = Label(input_root, text="Entrez l'adresse IP")
port_label = Label(input_root, text="Entrez le port")
connect_btn = Button(input_root, text="Connexion au serveur", command=set_ip, bg='#668cff', fg="white")

# affichage des éléments:
ip_label.pack(fill=X, side=TOP)
edit_text_ip.pack(fill=X, side=TOP)
port_label.pack(fill=X, side=TOP)
edit_text_port.pack(fill=X, side=TOP)
connect_btn.pack(fill=X, side=BOTTOM)

input_root.title(name)
input_root.geometry("400x500")
input_root.resizable(width=False, height=False)

input_root.mainloop()
# envoi des détails
name1=client.recv(1024).decode()
client.send(str.encode(name))
#Reception de la cle publique du serveur
rmsg=client.recv(1024)
pkey=pickle.loads(rmsg)
print("la clé publique de l'autre est :",pkey[0])
client.send(msg)

# 2: Interface graphique de la racine principale
root = Tk()
bgimage2 = PhotoImage(file ="images.png")
Label(root,image=bgimage2).place(relwidth=1,relheight=1)

# barre de défilement:
scrollbar = Scrollbar(root)
scrollbar.pack(side=RIGHT, fill=Y)
listbox = Listbox(root, yscrollcommand=scrollbar.set)
listbox.pack(fill=BOTH, side=TOP)
scrollbar.config(command=listbox.yview)

#Boutton d'envoi
button = Button(root, text="Envoyer le message", command=send, bg='#0030bf', fg="white")
button.pack(fill=X, side=BOTTOM)
edit_text = Entry(root)
edit_text.pack(fill=X, side=BOTTOM)

root.title(name)
root.geometry("400x500")
root.resizable(width=True, height=True)

threading.Thread(target=recv).start()

root.mainloop()
