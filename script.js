// 🌐 Cybersecurity & Ethical Hacking — Global Learning Tree Map
// Interactive Colorful Hierarchical Map | D3.js v7 | Offline-Ready

// ---------- 1. DATA: Full Cybersecurity Curriculum ----------
const DATA = {
  name: "Cybersecurity & Ethical Hacking",
  short: "World roadmap: Beginner → Expert | Tools, Phases, Skills",
  level: "All",
  children: [
    {
      name: "Foundations",
      color: "#00bcd4",
      short: "OS, Networking, Scripting, Environments",
      level: "Beginner",
      children: [
        { name: "Computer Basics", short: "Hardware, filesystems, processes" },
        { name: "Operating Systems", short: "Linux & Windows fundamentals", tools: ["Ubuntu", "Kali", "Windows 11"] },
        { name: "Networking Fundamentals", short: "TCP/IP, DNS, HTTP", tools: ["Wireshark", "tcpdump"] },
        { name: "Scripting", short: "Python, Bash automation", tools: ["Python", "Bash"] },
        { name: "Virtualization", short: "VMs, Containers", tools: ["VirtualBox", "Docker"] }
      ]
    },
    {
      name: "Reconnaissance & OSINT",
      color: "#f39c12",
      short: "Passive info gathering, social engineering, data mining",
      tools: ["whois", "shodan", "theHarvester", "OSINT Framework"],
      children: [
        { name: "Passive Recon", short: "Collect open-source info" },
        { name: "Active Recon", short: "Direct probing" },
        { name: "Social Engineering", short: "Phishing, manipulation" }
      ]
    },
    {
      name: "Scanning & Enumeration",
      color: "#ff5722",
      short: "Host discovery, port scanning, SMB/LDAP enumeration",
      tools: ["nmap", "masscan", "nbtscan", "enum4linux"],
      children: [
        { name: "Host Discovery", short: "Ping, ARP sweep" },
        { name: "Port Scanning", short: "TCP/UDP scans" },
        { name: "Service Detection", short: "Version and OS detection" }
      ]
    },
    {
      name: "Vulnerability Analysis",
      color: "#9c27b0",
      short: "Find weaknesses using scanners & manual testing",
      tools: ["Nessus", "OpenVAS", "Burp Suite", "searchsploit"]
    },
    {
      name: "Exploitation",
      color: "#e91e63",
      short: "Turning vulnerabilities into access",
      tools: ["Metasploit", "msfvenom", "sqlmap", "pwntools"],
      children: [
        { name: "Web Exploitation", short: "OWASP Top10, injections" },
        { name: "Network Exploitation", short: "Service & protocol flaws" },
        { name: "Binary Exploitation", short: "Memory, buffer overflow" }
      ]
    },
    {
      name: "Post-Exploitation",
      color: "#3f51b5",
      short: "Persistence, credential access, lateral movement",
      tools: ["Mimikatz", "Impacket", "Responder"],
      children: [
        { name: "Credential Dumping", short: "Extract hashes, passwords" },
        { name: "Persistence", short: "Backdoors, tasks, registry" },
        { name: "Lateral Movement", short: "Pivoting via SMB/WinRM" }
      ]
    },
    {
      name: "Privilege Escalation",
      color: "#8bc34a",
      short: "Gain higher privileges on systems",
      tools: ["LinPEAS", "WinPEAS", "GTFOBins"]
    },
    {
      name: "Red Teaming",
      color: "#f44336",
      short: "Adversary simulation, OPSEC, and campaign planning",
      tools: ["Cobalt Strike", "Empire", "Caldera"]
    },
    {
      name: "Blue Team & Forensics",
      color: "#2196f3",
      short: "Detection, monitoring, and response",
      tools: ["Splunk", "Elastic Stack", "OSQuery", "Volatility"],
      children: [
        { name: "SIEM", short: "Log collection, rule creation" },
        { name: "Incident Response", short: "Containment, triage, recovery" },
        { name: "Memory Forensics", short: "Analyze dumps" }
      ]
    },
    {
      name: "Cloud, Mobile & IoT Security",
      color: "#009688",
      short: "Modern attack surfaces and defenses",
      tools: ["ScoutSuite", "MobSF", "Frida", "CloudSploit"]
    },
    {
      name: "Reverse Engineering & Malware Analysis",
      color: "#607d8b",
      short: "Binary disassembly, static & dynamic malware analysis",
      tools: ["Ghidra", "IDA Free", "x64dbg"]
    },
    {
      name: "Threat Intelligence",
      color: "#795548",
      short: "MITRE ATT&CK, IOCs, actor profiling",
      tools: ["MISP", "Maltego", "VirusTotal"]
    },
    {
      name: "Certifications & Labs",
      color: "#4caf50",
      short: "Practice and professional paths",
      children: [
        { name: "Certifications", short: "Security+, CEH, OSCP, CRTO" },
        { name: "Labs", short: "TryHackMe, HackTheBox, CTFs" }
      ]
    },
    {
      name: "Ethics & Law",
      color: "#cddc39",
      short: "Responsible disclosure, compliance, ethics"
    }
  ]
};

// ---------- 2. D3 Tree Setup ----------
const svg = d3.select("#treeSvg");
const width = document.getElementById("treewrap").clientWidth * 0.66;
const height = document.getElementById("treewrap").clientHeight;
svg.attr("viewBox", [0, 0, width, height]);

const gLink = svg.append("g").attr("fill", "none").attr("stroke", "#555");
const gNode = svg.append("g").attr("cursor", "pointer");

const tree = d3.tree().size([height, width - 200]);
let root = d3.hierarchy(DATA);

function collapse(node) {
  if (node.children) {
    node._children = node.children;
    node._children.forEach(collapse);
    node.children = null;
  }
}
if (root.children) root.children.forEach(collapse);
root.x0 = height / 2;
root.y0 = 0;

let i = 0;
update(root);

function update(source) {
  const nodes = root.descendants();
  const links = root.links();
  tree(root);

  const node = gNode.selectAll("g").data(nodes, d => d.id || (d.id = ++i));
  const link = gLink.selectAll("path").data(links, d => d.target.id);

  // Draw links
  link.join(
    enter => enter.append("path")
      .attr("class", "link")
      .attr("stroke", "#444")
      .attr("stroke-width", 1.5)
      .attr("d", d3.linkHorizontal().x(d => d.y).y(d => d.x))
  );

  // Draw nodes
  const nodeEnter = node.enter().append("g")
    .attr("class", "node")
    .attr("transform", d => `translate(${source.y0},${source.x0})`)
    .on("click", (event, d) => {
      d.children = d.children ? null : d._children;
      update(d);
      showDetails(d.data);
    });

  nodeEnter.append("circle")
    .attr("r", 7)
    .attr("fill", d => d.data.color || "#58a6ff")
    .attr("stroke", "#fff")
    .attr("stroke-width", 1.5)
    .on("mouseover", (event, d) => showTooltip(event, d.data))
    .on("mouseout", hideTooltip);

  nodeEnter.append("text")
    .attr("dy", "0.32em")
    .attr("x", 12)
    .attr("font-size", 12)
    .attr("fill", "#ddd")
    .text(d => d.data.name);

  nodeEnter.transition().duration(400)
    .attr("transform", d => `translate(${d.y},${d.x})`);

  nodes.forEach(d => { d.x0 = d.x; d.y0 = d.y; });
}

// ---------- 3. Info Pane ----------
function showDetails(data) {
  document.getElementById("nodeTitle").textContent = data.name;
  document.getElementById("nodeShort").textContent = data.short || "—";
  const toolsDiv = document.getElementById("nodeTools");
  toolsDiv.innerHTML = "";
  if (data.tools) {
    data.tools.forEach(t => {
      const span = document.createElement("span");
      span.className = "tool";
      span.textContent = t;
      toolsDiv.appendChild(span);
    });
  }
}

// ---------- 4. Tooltip ----------
const tooltip = d3.select("body").append("div")
  .attr("class", "tooltip")
  .style("position", "absolute")
  .style("padding", "6px 10px")
  .style("background", "#111")
  .style("color", "#fff")
  .style("border-radius", "6px")
  .style("font-size", "12px")
  .style("visibility", "hidden");

function showTooltip(event, data) {
  tooltip.style("visibility", "visible")
    .html(`<b>${data.name}</b><br>${data.short || ""}`)
    .style("top", event.pageY + 10 + "px")
    .style("left", event.pageX + 10 + "px");
}

function hideTooltip() {
  tooltip.style("visibility", "hidden");
}
