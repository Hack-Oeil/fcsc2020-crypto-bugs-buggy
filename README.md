# FCSC 2020 Bugs Buggy

Le service RSSI de votre entreprise a besoin de votre expertise en cryptographie. La confidentialité de plusieurs fichiers a été compromise, indiquant qu’un attaquant a réussi à casser RSA-2048 sur cette machine.

Une première analyse faite par votre stagiaire indique que le seul processus d’intérêt qui tournait était /usr/local/bin/python3.8. Des signes de compromissions indiquent potentiellement l’installation d’une backdoor. On vous fournit ce binaire ainsi qu’un accès au prompt Python. (Note : il est inutile de regarder à l’extérieur du prompt Python pour cette épreuve, ni même d’essayer d’en sortir).

On vous donne également accès à un oracle de signature utilisé par l’attaquant qui tourne sur la machine compromise (oracle.py).

Votre but est de comprendre comment l’attaquant a procédé, de factoriser les clés qui sont générées puis de déchiffrer le contenu qui vous est envoyé.

Services :

Python : nc localhost 4001
Signature : nc localhost 4000
Note : l’épreuve Bugs Buggy du FCSC 2020 a été découpée en deux pour Hackropole. Une version plus simple est disponible ici : Bugs Buggy Easy.

[oracle.py](oracle.py)


[python3.8](python3.8)


Auteur : [Cryptanalyse](https://twitter.com/Cryptanalyse)

Origine : [Bugs Buggy](https://hackropole.fr/fr/challenges/crypto/fcsc2020-crypto-bugs-buggy/)


## Connectez vous en WEBSSH
> http://localhost


#### tentez 
> nc bugs-buggy.cyrhades.com:4000


-----------

## Ou directement avec netcat
> nc localhost:4000
et
> nc localhost:4001


-----------

## Installation manuel
Vous n'utilisez pas l'application **les CTFs de Cyrhades** ? C'est dommage !
Mais voici comment installer ce CTF manuellement :

> git clone https://github.com/Hack-Oeil/fcsc2020-crypto-bugs-buggy.git

> cd fcsc2020-crypto-bugs-buggy


-----------

## Sur le site officiel hackropole.fr
> https://hackropole.fr/fr/challenges/crypto/fcsc2020-crypto-bugs-buggy/