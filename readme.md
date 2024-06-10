execution du pt note to pt load.

compiler le code assembleur sur l'elf cc1c avec la commande :

nasm -f elf64 -o cc1.o cc1.s && ld -o cc1 cc1.o && ./cc1 cc1c

ensuite, avec la commande : 
readelf -Wl cc1c

on peut observer la transformation de tout le pt note en pt load
- p offset
- alignement
- taille mémoire
- taille fichier
- p vaddr
- p flag
- p type
ainsi que le point d'entré


avec l'outils ghexe on peut observer que le shell code c'est bien rajouté a la fin du fichier.



