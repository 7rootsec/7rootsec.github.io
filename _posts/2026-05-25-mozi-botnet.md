---
 title: "The Decentralized Ghost: A Technical Deep Dive into the Mozi IoT Botnet"
last_modified_at: 2026-05-24T14:40:02-05:00
categories:
  - Botnet
  - DDOS
  - shodan
  - CVE
  - C2
author_profile: false
---

### The Decentralized Ghost: A Technical Deep Dive into the Mozi IoT Botnet
**By: 7root**

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/45b168be-ef10-4576-9b10-1cb49b39f8df" />

The Internet of Things (IoT) landscape has seen many threats, but few have matched the resilience and scale of the **Mozi botnet**. Emerging in late 2019, Mozi quickly surpassed its predecessor, Mirai, to account for nearly **90% of all observed IoT network traffic** during its peak. What made Mozi uniquely dangerous was its total abandonment of centralized command-and-control (C2) servers in favor of a self-sustaining, peer-to-peer (P2P) architecture based on the **Distributed Hash Table (DHT)** protocol.

#### 1. Initial Access: The Multi-Vector Injection
Mozi recruits its "zombie army" through two primary methods: brute-forcing and vulnerability exploitation.

*   **Credential Brute-Forcing**: The botnet aggressively scans the internet for exposed **Telnet (Port 23)** and **SSH (Port 22)** interfaces. It uses automated dictionary attacks with hardcoded lists of default manufacturer credentials, such as `admin:admin` or `root:12345`.
*   **Command Injection (CMDi)**: Mozi utilizes a suite of recycled exploits from older malware like Mirai, Gafgyt, and IoT Reaper to gain remote access. A common method involves using a `wget` shell command to download and execute an architecture-specific binary (e.g., `mozi.a` or `mozi.m`) into temporary system directories like `/var/tmp`.

**Table 1: Key Vulnerabilities Exploited by Mozi**
| CVE / Vulnerability | Affected Hardware | Target Port |
| :--- | :--- | :--- |
| **CVE-2017-17215** | Huawei HG532 Home Gateways | 37215 |
| **CVE-2018-10561/2** | GPON Home Routers | 80 / 443 |
| **CVE-2014-8361** | Realtek SDK-based Devices | 52869 |
| **Eir D1000 RCI** | Eir D1000 Wireless Routers | Various |
| **Netgear R7000/R6400** | Netgear Routers (Command Injection) | Various |
| **MVPower DVR** | MVPower DVR (JAWS Webserver) | Various |

<img width="1408" height="768" alt="Gemini_Generated_Image_dqom81dqom81dqom-clean" src="https://github.com/user-attachments/assets/d8a9c2f8-f384-4303-9577-5ef03c4aba15" />

> *Description: This image would contrast a standard botnet (all bots connecting to one central server) with Mozi's decentralized mesh, where every bot acts as a node in a self-healing network.*

#### 2. The Backbone: Custom Extended DHT
Unlike traditional botnets, Mozi establishes its network by extending the standard **Distributed Hash Table (DHT)** protocol, the same technology used by BitTorrent.

*   **Node ID and Peer Discovery**: New nodes join the mesh by querying eight hardcoded public bootstrap nodes, such as `router.bittorrent.com:6881`, to find active peers. Each bot generates a unique **20-byte Node ID**, typically starting with the prefix `888888`.
*   **Hiding in Plain Sight**: To distinguish legitimate bot traffic from regular BitTorrent queries, Mozi nodes insert a custom **4-byte traffic flag** (e.g., `1:v4:flag`) into their UDP packets.
*   **Integrity and Signature Verification**: To ensure command integrity and prevent takeover by researchers, Mozi enforces **ECDSA384 digital signature verification**. Every configuration update synchronized across the mesh must be mathematically validated against the operator’s private key before a node will execute it.

#### 3. Runtime Evasion and Defense Impairment
Once a device is infected, Mozi employs several layers of obfuscation to stay hidden and secure its foothold.

*   **Process Masquerading**: The malware checks for the presence of `/usr/bin/python` on the host. If found, it renames its own process to **`sshd`**; otherwise, it mimics **`dropbear`** to blend into the list of running system services.
*   **Custom Packing**: Mozi samples are often packed with a customized version of UPX where the values for `p_file_size` and `p_blocksize` are erased to zero, preventing standard automated unpackers from working.
*   **Defensive Lockout**: The botnet uses `iptables` to block remote management ports like Telnet (23) and SSH (22). This effectively locks out the device owner and competing botnets, securing the host exclusively for the Mozi operator.

**Table 2: Mozi Configuration Command Tags (Decoded)**
| Tag | Command Type | Description |
| :--- | :--- | :--- |
| **[atk]** | Subtask | Trigger a DDoS attack (HTTP, TCP, UDP, SYN floods) |
| **[dr]** | Subtask | Download and execute an arbitrary payload from a URL |
| **[ud]** | Subtask | Update the Mozi bot executable to a newer version |
| **[rn]** | Subtask | Execute a specified system or customized shell command |
| **[idp]** | Subtask | Report bot metadata (IP, Port, CPU, Gateway) back to operators |
| **[hp]** | Control | Define the DHT node hash ID prefix |

<img width="1376" height="768" alt="Gemini_Generated_Image_l2g3h8l2g3h8l2g3 (1)" src="https://github.com/user-attachments/assets/2f9a5118-771e-4a7f-9c59-a70571c77a39" />


> *Description: A flow chart showing the stages: 1. Internet-wide scanning -> 2. Vulnerability/Brute-force exploit -> 3. Loader execution -> 4. Joining the DHT mesh -> 5. Receiving signed configuration updates.*

#### 4. Host Persistence Strategies
To survive system reboots and hardware resets, Mozi integrates itself deeply into the host's filesystem.

*   **Boot Scripts**: Mozi drops a persistent shell script, often named **`S95Baby.sh`**, into startup directories like `/etc/rcS.d` or `/etc/init.d`. It also appends execution commands to `/etc/rc.local`.
*   **Flash Storage**: On certain gateways (like Huawei), the malware copies its binary into persistent flash storage paths (e.g., `/mnt/jffs2/`) under names like `/usr/networks` or `/user/networktmp` to ensure it remains active even if the root directory is wiped.
*   **Disabling Remote Reset**: Mozi executes commands to disable the **TR-069 protocol (Port 7547)**. This prevents internet service providers from remotely resetting or updating the device firmware to remove the infection.

#### 5. The 2023 Mystery: The Kill-Switch
The botnet's reign came to an end in late 2023. In August and September, activity collapsed globally after a specialized configuration payload was pushed through the DHT network. This **kill-switch**—which was cryptographically signed with the operators' own private keys—instructed the bots to terminate their main processes and replace themselves with a non-malicious version. While active operations have ceased, millions of devices remain dormant with the malware still installed, awaiting a new signed command to reactivate.

***

### Conclusion
Mozi represented a paradigm shift in IoT warfare. By demonstrating that a decentralized, P2P architecture could successfully command millions of nodes without a central server, it set a blueprint for future botnets. While the 2023 kill-switch neutralized the active threat, the underlying problem—hundreds of millions of unmanaged, end-of-life IoT devices—remains. Mozi proved that the "ghost in the machine" is incredibly hard to exorcise once it has built a self-healing mesh.

***

### Thanks to 7root
Special thanks to 7root for providing the framework for this technical investigation. Your deep dives into these "ghosts in the mesh" continue to provide essential insights for the cybersecurity community.

***

📖 **Recommended Reading:** *The Next-Gen Information Security Professional* — How to move from technical expert to security leader before automation flattens your value. Available at [https://www.securityscientist.net/blog/recommended-book-the-next-gen-information-security-professional/](https://www.securityscientist.net/blog/recommended-book-the-next-gen-information-security-professional/).

