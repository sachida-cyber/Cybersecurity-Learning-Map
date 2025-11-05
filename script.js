/* script.js
   Clean, working D3 v7 collapsible tree using the full DATA you provided.
   - Collapses all nodes by default
   - Stable ids, enter/update/exit handled correctly
   - Info pane & tooltip
   - Search and level filter
*/

// ---------------- 1) FULL DATA (complete roadmap you gave)
const DATA = {
  "name": "Cybersecurity & Ethical Hacking",
  "short": "Complete road-map: beginner → expert, tools and sequence",
  "level": "All",
  "children": [
    {
      "name": "Foundations",
      "short": "Basic building blocks: OS, networking, programming",
      "level": "Beginner",
      "children": [
        {"name":"Computer Basics","short":"Hardware, filesystems, processes (Hinglish: computer kya hota hai)","level":"Beginner","tools":["none"]},
        {"name":"Operating Systems","short":"Linux fundamentals, Windows internals (Hinglish: Linux/Windows seekho)","level":"Beginner","tools":["Ubuntu","Kali","Windows 10/11"]},
        {"name":"Command Line","short":"bash, PowerShell basics for automation","level":"Beginner","tools":["bash","PowerShell"]},
        {"name":"Networking Fundamentals","short":"TCP/IP, DNS, HTTP, routing (Hinglish: network ka flow samjho)","level":"Beginner","tools":["Wireshark","tcpdump"],"children":[
          {"name":"OSI & TCP/IP Models","short":"Layers and responsibilities","level":"Beginner"},
          {"name":"Subnets & IPing","short":"CIDR, subnetting practice","level":"Beginner","tools":["ipcalc"]},
          {"name":"Ports & Services","short":"Common ports and their services","level":"Beginner"}
        ]},
        {"name":"Scripting & Programming","short":"Python, Bash for pentesting scripts","level":"Beginner","tools":["Python","pip","requests"]},
        {"name":"Version Control & Environment","short":"git, virtualization, containers","level":"Beginner","tools":["git","VirtualBox","Docker"]}
      ]
    },
    {
      "name": "Reconnaissance & OSINT",
      "short": "Passive info gathering, public data hunting",
      "level": "Beginner",
      "tools": ["whois","shodan","theHarvester","OSINT Framework"],
      "children": [
        {"name":"Passive Recon","short":"Publicly available info: websites, certs"},
        {"name":"Active Recon","short":"Probing targets carefully (Hinglish: halka probe)"},
        {"name":"Social Engineering Basics","short":"Human attack surfaces, phishing"}
      ]
    },
    {
      "name": "Scanning & Enumeration",
      "short": "Discover hosts, services, versions",
      "level": "Beginner → Intermediate",
      "tools":["nmap","masscan","nbtscan","rpcclient"],
      "children":[
        {"name":"Host Discovery","short":"Ping sweep, ARP, masscan","tools":["masscan","nmap -sn"]},
        {"name":"Port Scanning","short":"TCP/UDP scans, timing, evasion","tools":["nmap"]},
        {"name":"Service & Version Detection","short":"Identify software versions","tools":["nmap -sV"]},
        {"name":"Enumeration","short":"SMB, LDAP, SNMP, databases","tools":["enum4linux","ldapsearch","smbclient"]}
      ]
    },
    {
      "name": "Vulnerability Analysis",
      "short": "Find weaknesses and map CVEs",
      "level": "Intermediate",
      "tools":["OpenVAS","Nessus","Nmap NSE","searchsploit"],
      "children":[
        {"name":"Automated Scanning","short":"Use scanners but verify findings","tools":["Nessus","OpenVAS"]},
        {"name":"Manual Analysis","short":"Read configs, web app logic","tools":["Burp Suite","browser devtools"]},
        {"name":"Exploit Research","short":"Map CVE → PoC → exploit","tools":["exploit-db","GitHub","searchsploit"]}
      ]
    },
    {
      "name": "Web Application Security",
      "short": "OWASP Top10, web-specific attacks",
      "level": "Intermediate → Advanced",
      "tools":["Burp Suite","ZAP","sqlmap","ffuf"],
      "children":[
        {"name":"Injection (SQL/Command)","short":"sqlmap, prepared statements, input validation","tools":["sqlmap","Burp Intruder"]},
        {"name":"Authentication & Session","short":"Broken auth, session fixation"},
        {"name":"XSS (Reflected, Stored)","short":"Learn DOM and output encoding","tools":["Burp","DOM tools"]},
        {"name":"CSRF","short":"Anti-CSRF tokens, SameSite"},
        {"name":"File Upload & Deserialization","short":"RCE vectors via unsafe uploads"},
        {"name":"API Security","short":"REST/GraphQL: auth, rate-limits","tools":["Postman","Burp"]}
      ]
    },
    {
      "name": "Network & Infrastructure Attacks",
      "short": "Attacking services, protocols, devices",
      "level": "Intermediate → Advanced",
      "tools":["Metasploit","Responder","Bettercap"],
      "children":[
        {"name":"MITM & ARP Spoofing","short":"Intercept traffic on LAN","tools":["Ettercap","Bettercap"]},
        {"name":"LDAP/SMB/NetBIOS","short":"SMB shares, NTLM relay","tools":["Responder","ntlmrelayx"]},
        {"name":"Wireless Attacks","short":"WPA/WPA2 cracking, evil twin","tools":["aircrack-ng","wifite"]},
        {"name":"Active Directory Attacks","short":"Kerberos, AS-REP, AD enumeration","tools":["BloodHound","Impacket"]}
      ]
    },
    {
      "name": "Exploitation Techniques",
      "short": "Turn vulnerabilities into access",
      "level": "Intermediate → Advanced",
      "tools":["Metasploit","msfvenom","pwntools"],
      "children":[
        {"name":"Buffer Overflows Basics","short":"Memory, stack/heap basics","tools":["pwndbg","gdb"]},
        {"name":"Web Exploits","short":"RCE, LFI/RFI, SSRF"},
        {"name":"Binary Exploits","short":"ROP, format string attacks","tools":["radare2","Ghidra"]}
      ]
    },
    {
      "name": "Post-exploitation & Lateral Movement",
      "short": "Data exfiltration, pivoting, credential harvesting",
      "level": "Advanced",
      "tools":["Mimikatz","Responder","Metasploit"],
      "children":[
        {"name":"Credential Dumping","short":"Hash extraction, Mimikatz"},
        {"name":"Persistence","short":"Backdoors, scheduled tasks, services"},
        {"name":"Lateral Movement","short":"SMB/WinRM/SSH pivoting"},
        {"name":"Tunneling & Pivoting","short":"SSH port forwarding, SOCKS proxies"}
      ]
    },
    {
      "name": "Privilege Escalation",
      "short": "Local and network privilege gains",
      "level": "Advanced",
      "tools":["LinPEAS","WinPEAS","GTFOBins"],
      "children":[
        {"name":"Linux Escalation","short":"SUID, sudo misconfigs"},
        {"name":"Windows Escalation","short":"Unquoted paths, services"},
        {"name":"Kernel Exploits","short":"Rare, high-risk routes"}
      ]
    },
    {
      "name": "Red Teaming & Frameworks",
      "short": "Adversary emulation, campaign planning",
      "level": "Advanced",
      "tools":["Cobalt Strike","Empire","Caldera"],
      "children":[
        {"name":"Adversary Emulation","short":"TTP mapping, Purple Team ops"},
        {"name":"Operational Security","short":"OPSEC for red teams"},
        {"name":"Custom Tooling","short":"Build your own implants"}
      ]
    },
    {
      "name": "Defensive Skills (Blue Team)",
      "short": "Logging, detection, incident response",
      "level": "Intermediate → Advanced",
      "tools":["Splunk","Elastic Stack","OSQuery"],
      "children":[
        {"name":"Logging & SIEM","short":"Collect and analyze logs"},
        {"name":"Endpoint Detection","short":"EDR basics, rules"},
        {"name":"Network Monitoring","short":"IDS/IPS, Zeek"},
        {"name":"Incident Response","short":"Playbooks, containment"}
      ]
    },
    {
      "name": "Forensics & Incident Response",
      "short": "Disk/memory analysis and timeline building",
      "level": "Advanced",
      "tools":["Volatility","Sleuth Kit","Autopsy"],
      "children":[
        {"name":"Memory Forensics","short":"Dump analysis, malware traces"},
        {"name":"Disk Forensics","short":"File carving, timeline"},
        {"name":"Network Forensics","short":"PCAP analysis"}
      ]
    },
    {
      "name": "Reverse Engineering & Malware Analysis",
      "short": "Static/dynamic analysis of binaries and malware",
      "level": "Advanced",
      "tools":["Ghidra","IDA Free","x64dbg"],
      "children":[
        {"name":"Static Analysis","short":"Disassembly, strings, imports"},
        {"name":"Dynamic Analysis","short":"Sandboxing, debugging"},
        {"name":"Obfuscation & Packers","short":"Unpacking techniques"}
      ]
    },
    {
      "name": "Cryptography Basics",
      "short": "Hashes, encryption, PKI, TLS basics",
      "level": "Intermediate",
      "tools":["OpenSSL","hashcat"],
      "children":[
        {"name":"Hashing & Password Storage","short":"bcrypt, salts, cracking"},
        {"name":"Symmetric & Asymmetric","short":"AES vs RSA, when to use"},
        {"name":"TLS/PKI","short":"Certificates, chain of trust"}
      ]
    },
    {
      "name": "Cloud Security",
      "short": "AWS/Azure/GCP attack surface and misconfigurations",
      "level": "Intermediate → Advanced",
      "tools":["CloudSploit","ScoutSuite","Pacu"],
      "children":[
        {"name":"Identity & IAM","short":"Roles, policies, least privilege"},
        {"name":"Cloud Enumeration","short":"Metadata, buckets, IAM misconfigs"},
        {"name":"Cloud Exploitation","short":"Privilege escalation in cloud"}
      ]
    },
    {
      "name": "Mobile & IoT Security",
      "short": "Android/iOS app security, IoT device hacking",
      "level": "Intermediate → Advanced",
      "tools":["MobSF","Frida","Burp"],
      "children":[
        {"name":"Android Security","short":"APK analysis, intents"},
        {"name":"iOS Security","short":"Provisioning, sandboxing"},
        {"name":"IoT Device Hacking","short":"Firmware, UART, JTAG"}
      ]
    },
    {
      "name": "Threat Intelligence & OSINT 2.0",
      "short": "TTPs, indicators, actor profiling",
      "level": "Advanced",
      "tools":["MISP","Maltego","Recorded Future"],
      "children":[
        {"name":"TTP Mapping","short":"MITRE ATT&CK mapping"},
        {"name":"IOC Collection","short":"Hashes, domains, IPs"}
      ]
    },
    {
      "name": "Privacy & Legal Ethics",
      "short": "Rules of engagement, laws, responsible disclosure",
      "level": "All",
      "children":[
        {"name":"Laws & Compliance","short":"Local laws, GDPR, IT Act"},
        {"name":"Responsible Disclosure","short":"Coordinated disclosure process"},
        {"name":"Ethics","short":"What ethical hacking means"}
      ]
    },
    {
      "name": "Certifications & Career",
      "short": "Common certs and career ladders",
      "level": "All",
      "children":[
        {"name":"Entry Level","short":"CompTIA Security+, CEH basics"},
        {"name":"Mid Level","short":"OSCP, eJPT, Pentest+"},
        {"name":"Advanced","short":"OSCE, CRTO, Red Team Certificates"}
      ]
    },
    {
      "name": "Labs & Practice Platforms",
      "short": "Where to practice safely",
      "level": "All",
      "tools":["TryHackMe","HackTheBox","VulnHub","CTFs"],
      "children":[
        {"name":"Beginner Labs","short":"Intro rooms, Linux basics"},
        {"name":"Web App CTFs","short":"OWASP-top10 labs"},
        {"name":"Infrastructure CTFs","short":"AD/Network labs"}
      ]
    },
    {
      "name": "Tooling Master List",
      "short": "Quick list: core tools to learn and why",
      "level": "All",
      "children":[
        {"name":"nmap","short":"Port scanning and host discovery"},
        {"name":"Wireshark","short":"Packet analysis"},
        {"name":"Burp Suite","short":"Web proxy & scanner"},
        {"name":"Metasploit","short":"Exploit framework"},
        {"name":"sqlmap","short":"Automated SQL injection"},
        {"name":"Responder","short":"LLMNR/NBT-NS poisoning"},
        {"name":"Mimikatz","short":"Windows creds & hash extraction"},
        {"name":"hashcat","short":"Password cracking"},
        {"name":"Ghidra","short":"Reverse engineering"},
        {"name":"Volatility","short":"Memory forensics"}
      ]
    }
  ]
};

// ---------------- 2) Setup SVG and layout ----------------
const svg = d3.select("#treeSvg");
const wrap = document.getElementById("treewrap");
const infopane = document.getElementById("infopane");
const width = Math.max(700, wrap.clientWidth * 0.68);
const height = Math.max(400, wrap.clientHeight);
svg.attr("viewBox", [0, 0, width, height]).attr("preserveAspectRatio", "xMidYMid meet");

const gLinks = svg.append("g").attr("class", "links");
const gNodes = svg.append("g").attr("class", "nodes");

const tree = d3.tree().size([height - 40, width - 260]);

let root = d3.hierarchy(DATA);
root.x0 = height / 2;
root.y0 = 0;

// function to apply colors per top-level branch (so whole branch shares color)
const palette = ["#00bcd4","#f39c12","#ff5722","#9c27b0","#e91e63","#3f51b5","#8bc34a","#f44336","#2196f3","#009688","#607d8b","#795548","#4caf50","#cddc39"];
function assignBranchColors(node){
  if(!node.children) return;
  node.children.forEach((c, idx) => {
    // choose color from palette based on index
    c.data._branchColor = palette[idx % palette.length];
    // propagate to descendants
    c.each(d => d.data._branchColor = c.data._branchColor);
  });
}
assignBranchColors(root);

// Collapse helper
function collapse(d) {
  if (d.children) {
    d._children = d.children;
    d._children.forEach(collapse);
    d.children = null;
  }
}
if (root.children) root.children.forEach(collapse);

// stable id counter
let idCounter = 0;

update(root);

// ---------------- 3) Update function (enter/update/exit) ----------------
function update(source) {
  // compute new tree layout
  tree(root);

  const nodes = root.descendants();
  const links = root.links();

  // Nodes data-join (use unique stable id per node)
  const nodeSelection = gNodes.selectAll("g.node")
    .data(nodes, d => d.data.__id || (d.data.__id = ++idCounter));

  // EXIT
  const nodeExit = nodeSelection.exit()
    .transition().duration(300)
    .attr("transform", d => `translate(${source.y},${source.x})`)
    .style("opacity", 0)
    .remove();

  // ENTER
  const nodeEnter = nodeSelection.enter().append("g")
    .attr("class", "node")
    .attr("transform", d => `translate(${source.y0},${source.x0})`)
    .on("click", (event, d) => {
      // toggle
      if (d.children) { d._children = d.children; d.children = null; }
      else { d.children = d._children; d._children = null; }
      update(d);
      showDetails(d.data);
    });

  nodeEnter.append("circle")
    .attr("r", 1e-6)
    .attr("fill", d => d.data._branchColor || "#58a6ff")
    .attr("stroke", d => d._children ? "#000" : "#071023")
    .attr("stroke-width", 1.2)
    .on("mouseover", (event, d) => showTooltip(event, d.data))
    .on("mousemove", (event, d) => moveTooltip(event))
    .on("mouseout", hideTooltip);

  nodeEnter.append("text")
    .attr("dy", "0.32em")
    .attr("x", 12)
    .attr("fill", "#dceeff")
    .style("font-size", 12)
    .text(d => d.data.name);

  // UPDATE + ENTER merge
  const nodeMerge = nodeEnter.merge(nodeSelection);

  // Transition nodes to their new positions
  nodeMerge.transition().duration(350)
    .attr("transform", d => `translate(${d.y},${d.x})`);

  nodeMerge.select("circle").transition().duration(350)
    .attr("r", 7)
    .attr("fill", d => d.data._branchColor || "#58a6ff");

  // LINKS
  const linkSelection = gLinks.selectAll("path.link")
    .data(links, d => d.target.data.__id);

  // exit
  linkSelection.exit().transition().duration(300).style("opacity",0).remove();

  // enter
  const linkEnter = linkSelection.enter().append("path")
    .attr("class", "link")
    .attr("d", d => {
      const o = {x: source.x0, y: source.y0};
      return diagonal({source: o, target: o});
    });

  // update+enter
  linkEnter.merge(linkSelection).transition().duration(350)
    .attr("d", d => diagonal(d));

  // store positions for transition
  nodes.forEach(d => { d.x0 = d.x; d.y0 = d.y; });
}

// diagonal generator for horizontal links
function diagonal(d) {
  return d3.linkHorizontal()
    .x(d => d.y)
    .y(d => d.x)(d);
}

// ---------------- 4) Info pane ----------------
function showDetails(data) {
  document.getElementById("nodeTitle").textContent = data.name || "—";
  document.getElementById("nodeShort").textContent = data.short || "—";
  document.getElementById("nodeLevel").textContent = data.level || "—";
  const toolsDiv = document.getElementById("nodeTools");
  const resDiv = document.getElementById("nodeResources");
  toolsDiv.innerHTML = ""; resDiv.innerHTML = "";

  if (Array.isArray(data.tools)) {
    data.tools.forEach(t => {
      const s = document.createElement("span");
      s.className = "tag";
      s.textContent = t;
      toolsDiv.appendChild(s);
    });
  }
  if (Array.isArray(data.resources)) {
    data.resources.forEach(r => {
      const s = document.createElement("span");
      s.className = "tag";
      s.textContent = r;
      resDiv.appendChild(s);
    });
  }
}

// ---------------- 5) Tooltip ----------------
const tt = d3.select("body").append("div").attr("class","tooltip").style("visibility","hidden");
function showTooltip(event, data) {
  const html = `<strong>${escapeHtml(data.name || "")}</strong><div style="margin-top:6px;font-size:12px;color:#bfcfe8">${escapeHtml(data.short || "")}</div>`;
  tt.html(html).style("visibility","visible");
  moveTooltip(event);
}
function moveTooltip(event){
  const x = event.pageX + 12;
  const y = event.pageY + 12;
  tt.style("left", x + "px").style("top", y + "px");
}
function hideTooltip(){ tt.style("visibility","hidden"); }
function escapeHtml(str){ return String(str).replace(/[&<>"']/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[s])); }

// ---------------- 6) Search and Level Filter ----------------
const searchInput = document.getElementById("search");
const levelFilter = document.getElementById("levelFilter");
const resetBtn = document.getElementById("resetBtn");

searchInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") applyFilters();
});
levelFilter.addEventListener("change", applyFilters);
resetBtn.addEventListener("click", () => {
  searchInput.value = "";
  levelFilter.value = "All";
  // reassign colors & collapse all then update
  assignBranchColors(root);
  root.children && root.children.forEach(collapse);
  update(root);
});

function applyFilters(){
  const q = (searchInput.value || "").trim().toLowerCase();
  const level = levelFilter.value;

  // function to mark nodes that match
  root.each(d => {
    d.data._match = false;
    const name = (d.data.name || "").toLowerCase();
    const short = (d.data.short || "").toLowerCase();
    const tools = (d.data.tools || []).join(" ").toLowerCase();
    const levelText = (d.data.level || "").toLowerCase();
    // match search
    if (!q || name.includes(q) || short.includes(q) || tools.includes(q)) d.data._match = true;
    // match level
    if (level !== "All" && levelText) {
      if (!levelText.includes(level.toLowerCase())) d.data._match = false;
    }
  });

  // Expand to show matches: open branches that contain matches
  function markOpen(node){
    let anyChildMatch = false;
    if (node.children) {
      node.children.forEach(c => {
        const childHas = markOpen(c);
        anyChildMatch = anyChildMatch || childHas;
      });
    }
    // if node itself matches or any descendant matches -> open this node's chain
    if (node.data._match || anyChildMatch) {
      // ensure ancestor path is expanded (move from _children to children)
      if (node._children) {
        node.children = node._children;
        node._children = null;
      }
    } else {
      // collapse nodes that don't match
      if (node.children) {
        node._children = node.children;
        node._children.forEach(collapse);
        node.children = null;
      }
    }
    return node.data._match || anyChildMatch;
  }
  // start from root's children
  if (root.children) root.children.forEach(markOpen);
  update(root);
}

// initial details
showDetails(DATA);
