# windows-ansible
Powershell Script to ensure Ansible playbooks can run on Windows target hosts. This is for a cyber competition to make it easy.

```sh
Set-ExecutionPolicy Bypass -Scope Process -Force
.\bootstrap-winrm.ps1
```