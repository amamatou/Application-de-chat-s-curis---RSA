# On importe tous les modules requis
import socket
import threading
from tkinter import *
import pickle
import rsa
import binascii

# Saisie du nom du serveur
name=input("enter your name : ")

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
    
    # Definition du serveur:
    server = socket.socket()

    #lie le serveur à une adresse IP saisie et à un numéro de port spécifié.
    #Le client doit être conscient de ces paramètres
    server.bind((ip, int(port)))

    #serveur en ecoute de connexion
    server.listen()

    #Accepte une demande de connexion et stocke deux paramètres,
    # conn qui est un objet socket pour cet utilisateur, et addr
    # qui contient l'adresse IP du client qui s'est connecté
    global conn
    conn, addr = server.accept()

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
        # envoi du message chiffré
        conn.send(str(ctt).encode())
        #  barre de défilement:
        listbox.insert(END, message)
        edit_text.delete(0, END)


    # Apres l'envoi du message
    edit_text.delete(0, END)


# fonction de recuperation de message
def recv():
    while True:
        # reponse du client
        response_message =int(conn.recv(1024).decode())
        print(response_message)
        # decryptage du msg avec la clé privée du serveur
        decrypted_msg = rsa.decrypt(response_message, private)
        # barre de défilement::
        listbox.insert(END, name1 +" : "+ str(decrypted_msg))
        edit_text.delete(0, END)


# Interface graphique du serveur:

# 1: Interface graphique de la racine d'entrée(input root)
input_root = Tk()
bgimage = PhotoImage(file ="images.png")
Label(input_root,image=bgimage).place(relwidth=1,relheight=1)
edit_text_ip = Entry()
edit_text_port = Entry()
ip_label = Label(input_root, text="Entrer l'adresse IP:")
port_label = Label(input_root, text="Entrez le port:")
connect_btn = Button(input_root, text="Connexion", command=set_ip, bg='#668cff', fg="white")

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
#envoi des détails-----------
conn.send(str.encode(name))
name1=conn.recv(1024).decode()
#Envoi de la cle publique
conn.send(msg)
#Reception de la cle publique du client
rmsg=conn.recv(1024)
pkey=pickle.loads(rmsg)
print("la clé publique de l'autre est :",pkey[0])

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

button = Button(root, text="Envoyer le message", command=send, bg='#a33429', fg="white")
edit_text = Entry(root)

button.pack(fill=X, side=BOTTOM)
edit_text.pack(fill=X, side=BOTTOM)

root.title(name)
root.geometry("400x500")
root.resizable(width=True, height=True)

threading.Thread(target=recv).start()

root.mainloop()
