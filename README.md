# Sandbagility: Framework to analyze malwares

# Dependencies

  - Python 3.x: [https://www.python.org/](https://www.python.org/)
  - Winbagility: [https://github.com/Winbagility/Winbagility](https://github.com/Winbagility/Winbagility)

# Install

Sandbagility uses a modified version of VirtualBox (check Winbagility project).

## VirtualBox

- Uninstall other version of Virtualbox
- Download the latest version (r3) in [Winbagility github](https://github.com/Winbagility/Winbagility/tree/master/bin).

- Unzip the downloaded package
- The modified driver is not signed so to allow Windows to load unsigned driver :
    ````cmd
    bcdedit /set testsigning on
    ````
- Reboot the pc
- Install VirtualBox drivers, open a command line as Administator:
```` cmd
cd VBoxBin-r3\VBoxBin
set PATH=%PATH%;kmk
comregister.cmd
loadall.cmd
````
- Click yes to load unsiged driver
- Run VirtualBox.exe
- Try to run a VM
````
! WARNING ! Winbagility support only 1 cpu and 2048 MB of RAM (max)
````

## Winbagility

You can download a build version or compile it.
### Build

#### Build FDP.dll

- Download Visual Studio (2013, 2015, 2017)
- Download CMake
- Clone Winbagility
````cmd
git clone https://github.com/Winbagility/Winbagility
cd Winbagility
buildVS20XX.bat
````
- The built FDP dll in ``out_x64\Release``

### Download release

TODO

## Install python bindings
````cmd
git clone https://github.com/Winbagility/Winbagility
cd Winbagility\bindings\python
python3 setup.py install
````

## Install Sandbagility Framework

````cmd
git clone https://github.com/iNod3/sandbagility.git
cd sandbagility/Sandbagility
git clone https://github.com/iNod3/sandbagility-monitors.git Monitors
git clone https://github.com/iNod3/sandbagility-plugins.git Plugins
cd ..
python setup.py install
````

## Configure the environment

Sandbagility needs the microsoft pdb to introspect the machine.
Sandbagility uses the environment variable ````_NT_SYMBOLS_PATH ```` to search symbols.
You can use a local directory or an url.
````
set _NT_SYMBOLS_PATH=srv*C:\symbols*https://msdl.microsoft.com/download/symbols
````

## Try sandbagility
- Run a Vm in VirtualBox
- Get the name of the VM in virtualBox (e.g. Win10_x64)
- Download sandbagility examples:
````
git clone https://github.com/iNod3/sandbagility-examples.git
cd sandbagility-examples
python3 PsEnumSystemInformationTest.py Win10_x64
````
- The script must print all processes and drivers information.
