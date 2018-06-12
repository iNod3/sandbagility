# Installation

## Winbagility

Sandbagility s'appuie sur le binding Python proposé avec Winbagility pour pouvoir mettre en place les API de haut-niveau pour le monitoring des événements systèmes sous Windows.

### Compilation

* Installer Visual Studio 2017
* Télécharger Winbagility : https://github.com/Winbagility/
* Compiler Winbagility en suivant les instructions pour compiler les binding python.

### VirtualBox avec Fast Debugging Protocol

* Télécharger la version modifiée de VirtualBox : https://github.com/Winbagility/Winbagility/tree/master/bin
* Ajouter l'option `testsigning` au démarrage, cette option peut nécessiter la désactivation du SecureBoot

```bat
bcdedit /set testsigning on
```

* Dans un interpréteur de commande en tant qu'Administrateur, se placer dans le répertoire ```VBoxBin``` ;
* Exécuter les commandes suivantes

```bat
set PATH=%PATH%;kmk
comregister.cmd
loadall.cmd
```

A ce stade, VirtualBox devrait être opérationnel et fonctionner avec Windbg/DbgXShell.

## Sandbagility

### Prérequis

* Sandbagility s'appuie sur dbgeng.dll livrée avec Windbg/DbgXShell. Cette bibliothèque doit se trouver un répertoire accessible par LoadLibrary (cf. [Dynamic-Link Library Search Order](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682586(v=vs.85).aspx))

### Installation

* Cloner le repo principal, les monitors et les plugins

```
git clone git@github.com:iNod3/sandbagility.git
cd sandbagility/Sandbagility
git clone git@github.com:iNod3/sandbagility-monitors.git Monitors
git clone git@github.com:iNod3/sandbagility-plugins.git Plugins 
```

* installer sandbagility

```
python setup.py install
```

### Symboles

* Le framework peut télécharger directement les symboles pour Windows depuis le serveur de symbols de Microsoft

Sinon:

* Installer/Télécharger les symboles x64 et x32 pour la version de windows
* Ajouter une variable environnement `_NT_SYMBOLS_PATH` qui pointe vers le répertoire de symboles
