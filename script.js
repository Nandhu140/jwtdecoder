import * as jose from 'https://cdn.jsdelivr.net/npm/jose@5.2.0/+esm';

function debounce(func, wait) {
  let timeout;
  return function (...args) {
    clearTimeout(timeout);
    timeout = setTimeout(() => func.apply(this, args), wait);
  };
}

window.toggleMode = function () {
  const body = document.body;
  body.classList.toggle('normal-mode');
  body.classList.toggle('dark-mode');
  const button = document.querySelector('.toggle-mode');
  button.textContent = body.classList.contains('dark-mode') ? 'Toggle Normal Mode' : 'Toggle Dark Mode';
}

window.decodeJWT = function () {
  const jwt = document.getElementById('jwt-input').value.trim();
  const headerOutput = document.getElementById('header-output');
  const payloadOutput = document.getElementById('payload-output');
  const signatureOutput = document.getElementById('signature-output');
  const algorithmDisplay = document.getElementById('detected-algorithm');

  headerOutput.textContent = '';
  payloadOutput.textContent = '';
  signatureOutput.textContent = '';
  algorithmDisplay.textContent = 'None';

  if (!jwt) return;

  try {
    const [headerB64, payloadB64, signatureB64] = jwt.split('.');
    if (!headerB64 || !payloadB64 || !signatureB64) throw new Error('Invalid JWT format');

    const header = JSON.parse(atob(headerB64.replace(/-/g, '+').replace(/_/g, '/')));
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
    headerOutput.textContent = JSON.stringify(header, null, 2);
    payloadOutput.textContent = JSON.stringify(payload, null, 2);
    signatureOutput.textContent = signatureB64;

    const supportedAlgorithms = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'];
    algorithmDisplay.textContent = supportedAlgorithms.includes(header.alg) ? header.alg : 'Unknown';
  } catch (error) {
    headerOutput.textContent = 'Error: ' + error.message;
  }
}

window.encodeJWT = async function () {
  const header = document.getElementById('header-input').value.trim();
  const payload = document.getElementById('payload-input').value.trim();
  let secret = document.getElementById('encode-secret').value.trim();
  const output = document.getElementById('encoded-jwt');

  output.textContent = '';

  if (!header || !payload) {
    output.textContent = 'Header and payload must be valid JSON.';
    return;
  }

  try {
    const headerObj = JSON.parse(header);
    const algorithm = headerObj.alg || 'HS256';
    let key;

    if (algorithm.startsWith('HS')) {
      if (!secret) {
        secret = generateRandomKey(32);
        document.getElementById('encode-secret').value = secret;
      }
      key = new TextEncoder().encode(secret);
    } else {
      throw new Error('Unsupported algorithm');
    }

    const jwt = await new jose.SignJWT(JSON.parse(payload))
      .setProtectedHeader({ ...headerObj, alg: algorithm })
      .sign(key);
    output.textContent = jwt;
  } catch (error) {
    output.textContent = 'Error: ' + error.message;
  }
}

function generateRandomKey(length) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, byte => ('0' + byte.toString(16)).slice(-2)).join('');
}

window.copyJWT = function () {
  const jwt = document.getElementById('encoded-jwt').textContent;
  if (jwt) {
    navigator.clipboard.writeText(jwt).then(() => alert('JWT copied to clipboard!'));
  }
}

window.clearAll = function () {
  document.getElementById('jwt-input').value = '';
  document.getElementById('header-input').value = '';
  document.getElementById('payload-input').value = '';
  document.getElementById('encode-secret').value = '';
  document.getElementById('header-output').textContent = '';
  document.getElementById('payload-output').textContent = '';
  document.getElementById('signature-output').textContent = '';
  document.getElementById('encoded-jwt').textContent = '';
  document.getElementById('detected-algorithm').textContent = 'None';
}

window.debouncedDecodeJWT = debounce(window.decodeJWT, 300);
