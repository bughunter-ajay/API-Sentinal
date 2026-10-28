with open("UltronScan/ui/js/dalfox.js", "r", encoding="utf-8") as f:
    code = f.read()

old_body_extract = '''        const bodyData = ep.body_text || ep.data || ep.body || "";
        if (bodyData && typeof bodyData === "string") {
          try {
            const jObj = JSON.parse(bodyData);
            if (typeof jObj === "object" && jObj !== null && !Array.isArray(jObj)) {
              Object.keys(jObj).forEach(k => {
                if (!paramNames.includes(k)) paramNames.push(k);
              });
            }
          } catch (e) {
            const bodyMatches = bodyData.match(/([^&=?]+)=/g);
            if (bodyMatches) {
              bodyMatches.forEach(bm => {
                const k = bm.replace("=", "");
                if (!paramNames.includes(k)) paramNames.push(k);
              });
            }
          }
        }'''

new_body_extract = '''        const bodyData = ep.body_text || ep.data || ep.body || "";
        let parsedJson = null;
        if (typeof bodyData === "object" && bodyData !== null) {
          parsedJson = bodyData;
        } else if (typeof bodyData === "string" && bodyData.trim().length > 0) {
          try {
            parsedJson = JSON.parse(bodyData);
          } catch (e) {
            const bodyMatches = bodyData.match(/([^&=?]+)=/g);
            if (bodyMatches) {
              bodyMatches.forEach(bm => {
                const k = bm.replace("=", "");
                if (!paramNames.includes(k)) paramNames.push(k);
              });
            }
          }
        }

        if (parsedJson) {
          if (Array.isArray(parsedJson)) {
            parsedJson.forEach(item => {
              if (item && typeof item === "object") {
                Object.keys(item).forEach(k => {
                  if (!paramNames.includes(k)) paramNames.push(k);
                });
              }
            });
          } else if (typeof parsedJson === "object") {
            Object.keys(parsedJson).forEach(k => {
              if (!paramNames.includes(k)) paramNames.push(k);
            });
          }
        }'''

assert old_body_extract in code, "Could not find old_body_extract in dalfox.js"
code = code.replace(old_body_extract, new_body_extract)

with open("UltronScan/ui/js/dalfox.js", "w", encoding="utf-8") as f:
    f.write(code)

print("dalfox.js patched: JSON body keys and arrays will now display in Parameters column!")
