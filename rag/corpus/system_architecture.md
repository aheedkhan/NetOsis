# System Architecture Guidelines

## Standard Build
All internal servers are running Ubuntu 22.04 LTS (soon to be upgraded to 26.04 LTS). 
The default text editor is `nano`. `vim` is installed on database servers only.

## Credential Storage
As of Q2 2024, hardcoded passwords in `.bashrc` or scripts are strictly prohibited. 
All database connection strings should be stored in `/home/admin/.config/ops/` or fetched via the corporate secret manager. 

## Log Forwarding
All servers forward `/var/log/auth.log` to the SOC SIEM automatically. If `rsyslog` goes down, the NOC will be paged immediately. 
