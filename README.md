# Uniter network

For now, a small utility that allows to sync data between multiple computers over the network, using [Unison](https://github.com/bcpierce00/unison).

## How to use

Pre-requisite:
* computers with ssh ports open -- port 46 is for now default
* nmap installed on running machine
* unison installed on all machines
* a config file for now stored in `~/.bin/backup_hosts/hostlist`

The config file is filled manually and contains the signature of each device, as well as which folders to sync for each. The folder lines are indicated with a star, and having a single name means the same path is used for both machines. An example file syncing [cheatsheets](https://github.com/cheat/cheat) with 2 machines would look like:

```
ED25519 SHA256:******************************************* MachineName1 vogu
* Cheats /home/vogu/.config/cheat/cheatsheets/personal

RSA SHA256:******************************************* MachineName2 UserName2
* Cheats /home/vogu/.config/cheat/cheatsheets/personal /home/UserName2/.config/cheat/cheatsheets/personal
```

Then, based on the config file, the utility checks which known hosts are connected on the network, then syncs all possible files twice in a star configuration to ensure all files are up to date on all machines.

Nmap is used to check network availability, so using this on a public network is kinda rude.

## About this code

It's a bit messy, and is far from following all good practices, and should probably be split, organised, and a bunch of features should be added. It's just a minimum viable product to answer my most basic needs for now. But it works.

## Licensing
