// Cybersecurity & Ethical Hacking Tree Map — D3.js v7

// 1. ---- DATA ----
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
        {"name":"Computer Basics","short":"Hardware, filesystems, processes","level":"Beginner"},
        {"name":"Operating Systems","short":"Linux fundamentals, Windows internals","tools":["Ubuntu","Kali","Windows 10/11"]},
        {"name":"Command Line","short":"bash, PowerShell basics for automation","tools":["bash","PowerShell"]},
        {"name":"Networking Fundamentals","short":"TCP/IP, DNS, HTTP, routing","tools":["Wireshark","tcpdump"]}
      ]
    },
    {
      "name": "Reconnaissance & OSINT",
      "short": "Passive info gathering, public data hunting",
      "tools": ["whois","shodan","theHarvester","OSINT Framework"]
    },
    {
      "name": "Scanning & Enumeration",
      "short": "Discover hosts, services, versions",
      "tools":["nmap","masscan","nbtscan"]
    },
    {
      "name": "Vulnerability Analysis",
      "short": "Find weaknesses and map CVEs",
      "tools":["Nessus","OpenVAS","searchsploit"]
    },
    {
      "name": "Exploitation Techniques",
      "short": "Turn vulnerabilities into access",
      "tools":["Metasploit","msfvenom","pwntools"]
    },
    {
      "name": "Post-exploitation & Lateral Movement",
      "short": "Data exfiltration, pivoting, credential harvesting",
      "tools":["Mimikatz","Responder","Metasploit"]
    },
    {
      "name": "Privilege Escalation",
      "short": "Local and network privilege gains",
      "tools":["LinPEAS","WinPEAS","GTFOBins"]
    },
    {
      "name": "Red Teaming & Frameworks",
      "short": "Adversary emulation, campaign planning",
      "tools":["Cobalt Strike","Empire","Caldera"]
    },
    {
      "name": "Defensive Skills (Blue Team)",
      "short": "Detection, SIEM, and IR basics",
      "tools":["Splunk","Elastic Stack","OSQuery"]
    },
    {
      "name": "Labs & Practice Platforms",
      "short": "Where to practice safely",
      "tools":["TryHackMe","HackTheBox","VulnHub","CTFs"]
    }
  ]
};

// 2. ---- D3 Tree Setup ----
const svg = d3.select("#treeSvg");
const width = document.getElementById("treewrap").clientWidth * 0.66;
const height = document.getElementById("treewrap").clientHeight;
svg.attr("viewBox", [0, 0, width, height]);

const gLink = svg.append("g").attr("fill", "none").attr("stroke", "#555");
const gNode = svg.append("g").attr("cursor", "pointer");

const tree = d3.tree().size([height, width - 200]);
let root = d3.hierarchy(DATA);

// Collapse all nodes by default
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

update(root);

function update(source) {
  const nodes = root.descendants();
  const links = root.links();
  tree(root);

  const node = gNode.selectAll("g").data(nodes, d => d.id || (d.id = ++i));
  const link = gLink.selectAll("path").data(links, d => d.target.id);

  // Update links
  link.join(
    enter => enter.append("path")
      .attr("class", "link")
      .attr("d", d3.linkHorizontal().x(d => d.y).y(d => d.x))
  );

  // Update nodes
  const nodeEnter = node.enter().append("g")
    .attr("class", "node")
    .attr("transform", d => `translate(${source.y0},${source.x0})`)
    .on("click", (event, d) => {
      d.children = d.children ? null : d._children;
      update(d);
      showDetails(d.data);
    });

  nodeEnter.append("circle")
    .attr("r", 6)
    .attr("fill", d => d._children ? "#238636" : "#58a6ff");

  nodeEnter.append("text")
    .attr("dy", "0.32em")
    .attr("x", d => d._children ? -10 : 10)
    .attr("text-anchor", d => d._children ? "end" : "start")
    .text(d => d.data.name);

  nodeEnter.transition().duration(400)
    .attr("transform", d => `translate(${d.y},${d.x})`);

  nodes.forEach(d => { d.x0 = d.x; d.y0 = d.y; });
}

// 3. ---- Info Pane ----
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
