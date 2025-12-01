---
title: TryHackme - Printer Hacking 101
categories: [TryHackme]
tags: [TryHackme, Printing, ipp, Iot Hacking]
render_with_liquid: false
---

### **Printer Hacking 101**


Printer Hacking 101 is an Easy TryHackme Lab by  Swafox , this room she helps you to learn (and get hands on with) printer hacking and understand the basics of IPP

So let's Start by a small definition of Printer Hacking 

**Printer hacking** is the process of exploiting vulnerabilities in a printer or its associated services to gain unauthorized access, modify configurations, extract data, or use the device as an entry point into a network.

And We have 2 types of Printer hacking

---
### **Local Printer Hacking**

Local printer hacking happens when the attacker interacts with the printer **from the same physical network or machine**. This can include:

- Accessing the printer’s **USB, Wi-Fi Direct, or physical control panel**
    
- Exploiting **local print spooler services** (like Windows Print Spooler)
    
- Using tools such as **PRET**, **LPD**, or **IPP** when directly connected to the same LAN
    
- Capturing or modifying print jobs sent over the local network
    

### **Remote Printer Hacking**

Remote printer hacking occurs when the attacker interacts with the printer **over the internet or from a different network**, often using exposed services. This includes:

- Exploiting printers with **open ports** (e.g., 515 – LPD, 631 – IPP, 9100 – JetDirect)
    
- Exploiting vulnerabilities in the printer’s **web admin interface**
    
- Sending malicious print jobs or commands over **HTTP/HTTPS**, **SNMP**, or **JetDirect**
    
- Attacking cloud-connected printers or misconfigured remote printing setups
    


Unit 1 - Introduction : 

<img width="1170" height="858" alt="Pasted image 20251201165317" src="https://github.com/user-attachments/assets/7869eaee-1565-48a8-8732-7a5cc67b7f8f" />


After read this you understood that an Remote Printer hacking that hacked around 50.000 printers , printing out an messages  asking peoples to subscribe to PewDiePie

Unit 2 - IPP Port
<img width="1192" height="919" alt="Pasted image 20251201170235" src="https://github.com/user-attachments/assets/004eb9f9-2f19-47b3-961d-855f39f78f07" />


Unite 2 describe the reason behind the printer get hacked , its an open IPP port 

so what's the IPP :

Internet Printing Protocol or (IPP) is an network printing protocol used to manage print jobs and control printers over IP networks , it allow client to submit print jobs , configure printer settings , and more ... , the IPP main default port IS 631 (TCP) , IPP is used for : submitting print jobs over a network ,  Managing the print queue (pause, cancel, resume jobs)  , Querying printer/device status (ink levels, errors, paper tray info) , Cloud/remote printing (e.g., IPP Everywhere, AirPrint)

---


<img width="1076" height="178" alt="Pasted image 20251201171018" src="https://github.com/user-attachments/assets/77c4957e-6de5-461a-9f6c-95abe35d90b4" />


Answer :  631

Unit 3 -  Targeting & Exploitation

this unite get hands on Local Printer Hacking which suggest for  you an Printer Exploitation Toolkit
called `PRET` 

You can install it by running the following commands:

`git clone https://github.com/RUB-NDS/PRET && cd PRET  
`python3 -m pip install colorama pysnmP`


in Printer World , We have 3 types of printer Languages

## **What Are These 3 Printer Languages?**

**1. PostScript (PS)**  
A **programming language for printing**. It tells the printer how to draw shapes, text, and graphics.

**2. Printer Job Language (PJL)**  
A **control language** that manages the printer itself — settings, filesystem, jobs, configs.

**3. Printer Command Language (PCL)**  
A **basic command language** that controls how the page looks — fonts, layout, margins.

---

### **In one sentence:**

**PS draws the page, PCL formats the page, PJL controls the printer.**

The Unit contain an cheat sheet of Printer Security [hacking-printers.net/wiki/index.php/Printer_Security_Testing_Cheat_Sheet](http://hacking-printers.net/wiki/index.php/Printer_Security_Testing_Cheat_Sheet)

<img width="928" height="809" alt="Pasted image 20251201172647" src="https://github.com/user-attachments/assets/3603a0ef-a8bf-42f5-a6b4-7e69033e28fd" />


After Read this , you understood printer Hacking methods and there category

<img width="909" height="149" alt="Pasted image 20251201172608" src="https://github.com/user-attachments/assets/54dc5cf1-9a56-4dcb-9260-65a0050660e0" />


Answer :  `while true; do nc printer 9100; done`

<img width="1195" height="119" alt="Pasted image 20251201172838" src="https://github.com/user-attachments/assets/a5c6d8d8-a069-4bfa-b9e0-247cdb7399bb" />


   
Answer : Buffer overflows

![[Pasted image 20251201173228.png]]

go to http://MACHINE-IP:631

631 : IPP  Port

<img width="1419" height="940" alt="Pasted image 20251201173527" src="https://github.com/user-attachments/assets/dd0ef181-6764-4b36-b23a-2703ec4490a0" />



you see this dashboard its seems an Unauthorized access to printer management  dashboard with out authentication 

- go to Printers , you see all printers with there information's

<img width="1456" height="937" alt="Pasted image 20251201173717" src="https://github.com/user-attachments/assets/1b6a9ac4-4ced-4ad2-9509-11ac0f08628f" />


Answer : 	Skidy's basement

<img width="1859" height="873" alt="Pasted image 20251201174228" src="https://github.com/user-attachments/assets/43ce629d-458f-47c3-beb9-b27613a5df0c" />


Change the status from maintenance to print test   page to perform an printing test

<img width="1199" height="117" alt="Pasted image 20251201173935" src="https://github.com/user-attachments/assets/f8fd8f5c-14a2-46af-bebb-149ea96a7a6b" />


Answer : 1k


— End of Write-up —
© 2025 7rootSec — Ethical Hacking | Research | Write-ups
