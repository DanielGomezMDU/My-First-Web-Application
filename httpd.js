const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const querystring = require('querystring'); // Add the querystring import

// Preventing for a DoS attack -> Implement a request timeout: Setting a timeout for incoming requests 
// to prevent them from taking too long. If a request takes too long, it will be terminated.

// Setting a request timeout
const requestTimeout = 30000; // 30 seconds in milliseconds

const server = http.createServer((req, res) => {
  // Set a timer for the request
  const requestTimer = setTimeout(() => {
    res.writeHead(408, { 'Content-Type': 'text/plain' });
    res.end('Request Timeout');
  }, requestTimeout);

  // Add this line to clear the timer when the request is finished
  res.on('finish', () => {
    clearTimeout(requestTimer);
  });

  // Parse the URL to extract the path and query parameters
  const parsedUrl = url.parse(req.url, true);
  const { pathname, query } = parsedUrl;

  // Check for the root path or "/information" path
  if (pathname === '/' || pathname === '/information') {
    // Serve the main page or information page based on the path
    if (pathname === '/') {
      servePage(res, 'index.html');
    } else if (pathname === '/information') {
      informationHandler(req, res, query);
    }
  } else {
    // Serve static files for other paths
    staticFileHandler(req, res, query);
  }
});

function staticFileHandler(req, res, query) {
  const filePath = path.join(__dirname, 'public', req.url);

  fs.stat(filePath, (err, stats) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('File not found');
    } else {
      if (stats.isDirectory()) {
        const indexFilePath = path.join(filePath, 'index.html');

        fs.access(indexFilePath, fs.constants.F_OK, (err) => {
          if (err) {
            serveDirectoryListing(res, filePath);
          } else {
            serveFile(res, indexFilePath);
          }
        });
      } else {
        serveFile(res, filePath);
      }
    }
  });
}

function servePage(res, pageName) {
  const filePath = path.join(__dirname, 'public', pageName);

  fs.readFile(filePath, 'utf8', (err, pageContent) => {
    if (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('Internal Server Error');
    } else {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(pageContent);
    }
  });
}

  // Preventing for a DoS attack -> Simple validation in a for loop that checks if all URL parameters are non-empty strings. 
  // If any parameter is empty, it responds with an HTTP 400 (Bad Request) status code and an error message.

  function informationHandler(req, res, query) {
    if (req.method === 'GET') {
      // Handle GET request with query parameters
      const templatePath = path.join(__dirname, 'templates', 'information.html');
  
      // Validate query parameters
      let isValid = true;
  
      for (const [key, value] of Object.entries(query)) {
        if (!key.trim() || !value.trim()) {
          isValid = false;
          break;
        }
      }
  
      if (!isValid) {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('Bad Request: Invalid query parameters');
        return;
      }
  
      fs.readFile(templatePath, 'utf8', (err, template) => {
        if (err) {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end('Internal Server Error');
        } else {
          // Encode HTML entities in query parameters
          for (const [key, value] of Object.entries(query)) {
            query[key] = encodeHtmlEntities(value);
          }
  
          // Encode HTML attributes in query parameters
          for (const [key, value] of Object.entries(query)) {
            query[key] = encodeHtmlAttributes(value);
          }
  
          // Replace placeholders in the template with request information
          const replacedTemplate = template
            .replace('{{method}}', 'GET')
            .replace('{{path}}', '/information')
            .replace('{{query}}', JSON.stringify(query));
  
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(replacedTemplate);
        }
      });
    } else {
      // Handle other HTTP methods if needed
      res.writeHead(405, { 'Content-Type': 'text/plain' });
      res.end('Method Not Allowed');
    }
  }
  
  
  // Preventing for a XSS attack -> HTML Entity Encoding: We convert the following characteres (untrusted input) 
  // into a safe form to be aware of the XSS attacks

  // Function to encode HTML entities
  function encodeHtmlEntities(unsafe) {
    return unsafe
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#x27;");
  }

    // Preventing for a XSS attack -> HTML Attribute Encoding: We take a string as input and encode all non-alphanumeric characters 
    // in the &#xHH; format. Alphanumeric characters (letters A-Z, a-z, and digits 0-9) will remain unencoded


  function encodeHtmlAttributes(unsafe) {
    return unsafe
      .split('')
      .map(char => {
        const charCode = char.charCodeAt(0);
        if (
          (charCode >= 48 && charCode <= 57) || // Digits 0-9
          (charCode >= 65 && charCode <= 90) || // Uppercase letters A-Z
          (charCode >= 97 && charCode <= 122)   // Lowercase letters a-z
        ) {
          // Characters A-Z, a-z, 0-9 remain unencoded
          return char;
        } else {
          // Encode other characters using the HTML Entity format &#xHH;
          return `&#x${charCode.toString(16).toUpperCase()};`;
        }
      })
      .join('');
  }
  

function serveFile(res, filePath) {
  const extname = path.extname(filePath);
  let contentType = 'text/html';

  if (extname === '.jpg' || extname === '.jpeg') {
    contentType = 'image/jpeg';
  } else if (extname === '.png') {
    contentType = 'image/png';
  } else if (extname === '.css') {
    contentType = 'text/css';
  } else if (extname === '.js') {
    contentType = 'text/javascript';
  }

  res.writeHead(200, { 'Content-Type': contentType });

  const fileStream = fs.createReadStream(filePath);
  fileStream.pipe(res);
}

function serveDirectoryListing(res, dirPath) {
  fs.readdir(dirPath, (err, files) => {
    if (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('Internal Server Error');
    } else {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('Directory Listing:\n' + files.join('\n'));
    }
  });
}

server.listen(8000)




