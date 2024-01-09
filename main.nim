import std/distros, std/times

type
  DebianBasedDistros = array[8, string]
  ArchBasedDistros = array[7, string]
  GentooBasedDistros = array[6, string]
  CentOSBasedDistros = array[5, string]
  FedoraBasedDistros = array[3, string]
  openSUSEBasedDistros = array[3, string]
  SlackwareBasedDistros = array[3, string]
  

let Debian: DebianBasedDistros = ["Debian", "Ubuntu", "Linux Mint", "elementary OS", "Pop!_OS", "Deepin", "Kali Linux", "MX Linux"]
let Arch : ArchBasedDistros = ["Arch Linux", "Manjaro Linux", "EndeavourOS", "Artix Linux", "ArchBang Linux", "Arcolinux", "Garuda Linux"]
let Gentoo : GentooBasedDistros = ["Gentoo", "Calculate Linux", "Funtoo Linux", "Sabayon Linux", "Gentoo Studio", "Redcore Linux"] 
let CentOS : CentOSBasedDistros = ["CentOS", "Red Hat Enterprise Linux", "Oracle Linux", "Rocky Linux", "AlmaLinux"]
let Fedora : FedoraBasedDistros = ["Fedora", "Redcore Linux", "Korora"]
let openSUSE : openSUSEBasedDistros = ["openSUSE", "GeckoLinux", "Krypton Linux"]
let Slackware : SlackwareBasedDistros = ["Slackware", "Zenwalk Linux", "Absolute Linux"]
