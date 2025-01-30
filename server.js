const express = require("express");
const fetch = require("node-fetch");
const path = require("path");
const cors = require("cors");
const app = express();
const PORT = 3000;

// Enable CORS
app.use(cors());

// Serve static files (for frontend)
app.use(express.static(path.join(__dirname, "public")));

// Validate IP address format using a regex pattern
const isValidIP = (ip) => {
    const regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return regex.test(ip);
};

// AbuseIPDB API Route
app.get("/api/abuseipdb", async (req, res) => {
    const { ip } = req.query;
    const abuseKey = "2e0272c72bbd67cb0180ad31a66d51966785338cc41e7434560c723b5e66622215525ca13c9896eb";  // Replace with your AbuseIPDB key

    if (!ip || !isValidIP(ip)) {
        return res.status(400).json({ error: "Valid IP address is required." });
    }

    try {
        const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
            headers: {
                "Key": abuseKey,
                "Accept": "application/json"
            }
        });

        if (!response.ok) {
            return res.status(500).json({ error: "Error fetching data from AbuseIPDB", details: response.statusText });
        }

        const data = await response.json();
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: "Error fetching data from AbuseIPDB", details: error.message });
    }
});

// VirusTotal API Route
app.get("/api/virustotal", async (req, res) => {
    const { ip } = req.query;
    const virusKey = "bd159d67bed1d755c5ba6485660cb16dfd47d31235c092c50265804df800776b";  // Replace with your VirusTotal key

    if (!ip || !isValidIP(ip)) {
        return res.status(400).json({ error: "Valid IP address is required." });
    }

    try {
        const response = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
            headers: {
                "x-apikey": virusKey
            }
        });

        if (!response.ok) {
            return res.status(500).json({ error: "Error fetching data from VirusTotal", details: response.statusText });
        }

        const data = await response.json();
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: "Error fetching data from VirusTotal", details: error.message });
    }
});

// Start the server
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));