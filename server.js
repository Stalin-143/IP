const express = require("express");
const fetch = require("node-fetch");
const path = require("path");
const app = express();
const PORT = 3000;

// Serve static files
app.use(express.static(path.join(__dirname, "public")));

// AbuseIPDB API Route
app.get("/api/abuseipdb", async (req, res) => {
    const { ip } = req.query;
    const abuseKey = "2e0272c72bbd67cb0180ad31a66d51966785338cc41e7434560c723b5e66622215525ca13c9896eb";

    if (!ip) {
        return res.status(400).json({ error: "IP address is required." });
    }

    try {
        const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
            headers: {
                "Key": abuseKey,
                "Accept": "application/json"
            }
        });
        const data = await response.json();
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: "Error fetching data from AbuseIPDB", details: error.message });
    }
});

// VirusTotal API Route
app.get("/api/virustotal", async (req, res) => {
    const { ip } = req.query;
    const virusKey = "YOUR_VIRUSTOTAL_API_KEY";

    if (!ip) {
        return res.status(400).json({ error: "IP address is required." });
    }

    try {
        const response = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
            headers: {
                "x-apikey": virusKey
            }
        });
        const data = await response.json();
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: "Error fetching data from VirusTotal", details: error.message });
    }
});

// Start the server
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
