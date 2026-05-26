const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const dir = path.resolve(__dirname, "..", "wasm");
const files = fs.readdirSync(dir).filter((file) => file.endsWith(".wasm"));

for (const file of files) {
  const data = fs.readFileSync(path.join(dir, file));
  const base64Data = data.toString("base64");
  const parsedName = path.parse(file);

    const sha256 = crypto.createHash("sha256").update(data).digest("hex");

    const jsonObj = {
      name: parsedName.name,
      data: base64Data,
      // legacy short hash kept for compatibility
      hash: crypto.createHash("sha1").update(data).digest("hex").substring(0, 8),
      sha256,
    };

    // Optionally compute an HMAC if a base64 key is provided via WASM_HMAC_KEY
    if (process.env.WASM_HMAC_KEY) {
      const key = Buffer.from(process.env.WASM_HMAC_KEY, "base64");
      const hmac = crypto.createHmac("sha256", key).update(data).digest("base64");
      jsonObj.hmac = hmac;
    }

    const json = JSON.stringify(jsonObj);

  fs.writeFileSync(path.join(dir, `${file}.json`), json);
}
