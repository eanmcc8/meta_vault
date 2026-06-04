// vault-decryptor.js
// This module attaches Vault Decryptor logic to VaultExtractor.prototype
(function(){
  if (typeof window === 'undefined' || typeof window.VaultExtractor === 'undefined') {
    // In case the script is loaded before the class, wait until DOMContentLoaded
    document.addEventListener('DOMContentLoaded', function() {
      if (typeof window.VaultExtractor !== 'undefined') {
        attachMethods(window.VaultExtractor.prototype);
      }
    });
  } else {
    attachMethods(window.VaultExtractor.prototype);
  }

  function attachMethods(proto) {
    // Helper: get plaintext without unresolved placeholders
    proto.getSanitizedPlainText = function() {
      const output = document.getElementById('decryptedOutput');
      let text = this.decryptedOutputPlainText || (output ? output.textContent : '');
      // Remove any unresolved placeholders like [ETH_ACCOUNTS_0]
      text = text.replace(/\[ETH_ACCOUNTS_\d+\]\n?/g, '');
      // Trim trailing spaces/newlines
      return text.replace(/[\s\n]+$/g, '');
    };
    // Helper: validate and format ETH address with Etherscan link
    proto.isEthAddress = function(addr) {
      return typeof addr === 'string' && /^0x[0-9a-fA-F]{40}$/.test(addr);
    };
    proto.linkEthAddress = function(addr) {
      if (!this.isEthAddress(addr)) return addr;
      const url = `https://etherscan.io/address/${addr}`;
      return `<a href="${url}" target="_blank" rel="noopener noreferrer" title="Open in Etherscan" style="color: #4CAF50; text-decoration: none; cursor: pointer;" onmouseover="this.style.textDecoration='underline'" onmouseout="this.style.textDecoration='none'">${addr}</a>`;
    };
    // Password visibility + button wiring
    proto.setupVaultDecryptorEvents = function() {
      if (!this.vaultDataInput || !this.vaultPassword || !this.decryptBtn) {
        console.error('Vault decryptor elements not found');
        return;
      }

      const togglePassword = document.getElementById('togglePassword');
      const monkeyEmoji = document.getElementById('monkeyEmoji');
      if (togglePassword && monkeyEmoji) {
        togglePassword.addEventListener('click', () => {
          this.vaultPassword.type = 'text';
          togglePassword.style.display = 'none';
          monkeyEmoji.style.display = 'inline-block';
        });
        monkeyEmoji.addEventListener('click', () => {
          this.vaultPassword.type = 'password';
          monkeyEmoji.style.display = 'none';
          togglePassword.style.display = 'inline-block';
        });
      }

      this.vaultDataInput.addEventListener('input', this.updateDecryptButtonState.bind(this));
      this.vaultPassword.addEventListener('input', this.updateDecryptButtonState.bind(this));

      this.decryptBtn.addEventListener('click', () => this.decryptVaultData());

      if (this.copyDecryptedBtn) {
        this.copyDecryptedBtn.addEventListener('click', () => this.copyDecryptedData());
      }
      if (this.saveDecryptedBtn) {
        this.saveDecryptedBtn.addEventListener('click', () => this.saveDecryptedData());
      }
      if (this.clearDecryptorBtn) {
        this.clearDecryptorBtn.addEventListener('click', () => this.clearDecryptor());
      }
    };

    proto.updateDecryptButtonState = function() {
      const hasVaultData = this.vaultDataInput.value.trim().length > 0;
      const hasPassword = this.vaultPassword.value.trim().length > 0;
      this.decryptBtn.disabled = !(hasVaultData && hasPassword);
    };

    proto.decryptVaultData = async function() {
      const vaultDataStr = this.vaultDataInput.value.trim();
      const password = this.vaultPassword.value.trim();
      if (!vaultDataStr || !password) {
        this.showNotification('Please provide both vault data and password', 'error');
        return;
      }
      this.decryptBtn.disabled = true;
      this.decryptBtn.innerHTML = '<div class="loading"></div> Parsing input...';
      try {
        const vault = this.parseVaultData(vaultDataStr);
        if (!vault) throw new Error('Invalid vault data format');
        // update progress
        this.decryptBtn.innerHTML = '<div class="loading"></div> Deriving key...';
        const onProgress = async (stage) => {
          this.decryptBtn.innerHTML = `<div class="loading"></div> ${stage}`;
          await new Promise(r => setTimeout(r, 0));
        };
        const decrypted = await this.performActualDecryption(password, vault, onProgress);
        this.decryptBtn.innerHTML = '<div class="loading"></div> Rendering...';
        this.displayDecryptedData(decrypted);
      } catch (error) {
        console.error('Decryption error:', error);
        this.decryptedOutput.textContent = `Error: ${error.message}`;
      } finally {
        this.decryptBtn.disabled = false;
        this.decryptBtn.innerHTML = '<span class="btn-icon">🔑</span> Decrypt Vault Data';
        this.updateDecryptButtonState();
      }
    };

    proto.loadCryptoJS = function() {
      return new Promise((resolve, reject) => {
        if (window.CryptoJS) {
          resolve(window.CryptoJS);
          return;
        }
        const script = document.createElement('script');
        script.src = 'js/crypto-js.min.js';
        script.onload = () => resolve(window.CryptoJS);
        script.onerror = () => reject(new Error('Failed to load crypto-js library'));
        document.head.appendChild(script);
      });
    };

    proto.parseVaultData = function(data) {
      try {
        const vault = JSON.parse(data);
        if (!vault.data || !vault.iv || !vault.salt) {
          throw new Error('Missing required fields: data, iv, or salt');
        }
        if (!vault.keyMetadata) {
          vault.keyMetadata = { algorithm: 'PBKDF2', params: { iterations: 600000 } };
        }
        return vault;
      } catch (e) {
        throw new Error('Invalid JSON format');
      }
    };

    proto.base64ToArrayBuffer = function(base64) {
      const binaryString = atob(base64);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      return bytes.buffer;
    };

    proto.performActualDecryption = async function(password, vault, onProgress) {
      const encoder = new TextEncoder();
      const decoder = new TextDecoder();
      const iterations = vault.keyMetadata?.params?.iterations || 600000;
      const salt = this.base64ToArrayBuffer(vault.salt);
      const iv = this.base64ToArrayBuffer(vault.iv);
      const encryptedData = this.base64ToArrayBuffer(vault.data);
      try {
        if (onProgress) await onProgress('Deriving key...');
        const passwordBuffer = encoder.encode(password);
        const keyMaterial = await crypto.subtle.importKey('raw', passwordBuffer, 'PBKDF2', false, ['deriveKey']);
        const derivedKey = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
        if (onProgress) await onProgress('Decrypting...');
        const decryptedBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, derivedKey, encryptedData);
        if (onProgress) await onProgress('Parsing wallet...');
        const decryptedString = decoder.decode(decryptedBuffer);
        return JSON.parse(decryptedString);
      } catch (error) {
        console.error('Decryption error:', error);
        throw new Error('Failed to decrypt: ' + error.message);
      }
    };

    proto.privateKeyToAddress = function(privateKey) {
      try {
        const cleanKey = privateKey.trim().startsWith('0x') ? privateKey.trim().substring(2) : privateKey.trim();
        if (!/^[0-9a-fA-F]{64}$/.test(cleanKey)) return null;
        const wallet = new ethers.Wallet('0x' + cleanKey);
        return wallet.address;
      } catch (error) {
        console.error('Error converting private key to address:', error);
        return null;
      }
    };

    proto.displayDecryptedData = function(walletData) {
      // Build HTML (rich) and plain text (for saving/copy) in parallel
      let output = "<div style='white-space: pre-wrap; font-family: monospace; color: #e0e0e0;'><span style='color: #FFA500; font-weight: bold;'>=== DECRYPTED WALLET INFORMATION ===</span><br><br>";
      let plainLines = [];
      plainLines.push('=== DECRYPTED WALLET INFORMATION ===');
      plainLines.push('');
      if (Array.isArray(walletData)) {
        walletData.forEach((keyring, index) => {
          output += `<span style='color: #3498db; font-weight: bold;'>KEYRING ${index + 1}</span> (${keyring.type || 'Unknown Type'}):<br><br>`;
          plainLines.push(`KEYRING ${index + 1} (${keyring.type || 'Unknown Type'}):`);
          if (keyring.data.mnemonic) {
            let mnemonic = keyring.data.mnemonic;
            if (Array.isArray(mnemonic)) {
              mnemonic = String.fromCharCode(...mnemonic);
            }
            output += `Seed Phrase: <span style='color: #4CAF50;'>${mnemonic}</span> <button id="showEthBtn-${index}" class="btn btn-small" style="background: #666666; color: #ffffff; margin-left: 8px;">Show first 3 ETH accounts</button>\n`;
            output += `<div id="ethAccounts-${index}" style="margin: 6px 0 0 0;"></div>`;
            plainLines.push(`Seed Phrase: ${mnemonic}`);
            // Placeholder for lazy ETH accounts to be inserted under this keyring
            plainLines.push(`[ETH_ACCOUNTS_${index}]`);
          }
          if (keyring.data.accounts && Array.isArray(keyring.data.accounts)) {
            output += 'Accounts:\n';
            keyring.data.accounts.forEach((account, accIndex) => {
              const maybeLink = this.isEthAddress(account) ? this.linkEthAddress(account) : account;
              output += `  Account ${accIndex + 1}: ${maybeLink}\n`;
              plainLines.push(`Account ${accIndex + 1}: ${account}`);
            });
          }
          if (keyring.data.privateKeys && Array.isArray(keyring.data.privateKeys)) {
            output += "<div style='margin-bottom: 15px;'>Private Keys:</div>";
            plainLines.push('Private Keys:');
            keyring.data.privateKeys.forEach((key, keyIndex) => {
              let privateKey = key;
              if (Array.isArray(key)) {
                privateKey = '0x' + key.map(b => b.toString(16).padStart(2, '0')).join('');
              }
              output += `<div style='margin: 10px 0 10px 20px;'>`;
              output += `<div>Key ${keyIndex + 1}: <span class="private-key">${privateKey}</span></div>`;
              const ethAddress = this.privateKeyToAddress(privateKey);
              if (ethAddress) {
                output += `<div>Ethereum Address: ${this.linkEthAddress(ethAddress)}</div>`;
              }
              output += '</div>';
              plainLines.push(`  Key ${keyIndex + 1}: ${privateKey}`);
              const addrForPlain = this.privateKeyToAddress(privateKey);
              if (addrForPlain) plainLines.push(`    Ethereum Address: ${addrForPlain}`);
            });
          }
          if (keyring.data.addresses && keyring.data.privateKeys) {
            output += "<div style='margin: 15px 0 10px 0;'>Address-Private Key Pairs:</div>";
            plainLines.push('Address-Private Key Pairs:');
            keyring.data.addresses.forEach((address, addrIndex) => {
              const privateKey = keyring.data.privateKeys[addrIndex];
              output += `<div style='margin: 10px 0 10px 20px;'>`;
              output += `<div>Address: ${this.linkEthAddress(address)}</div>`;
              output += `<div>Private Key: <span class="private-key">${privateKey}</span></div>`;
              const ethAddress = this.privateKeyToAddress(privateKey);
              if (ethAddress) {
                output += `<div>Ethereum Address: <span style='color: #4CAF50;'>${ethAddress}</span></div>`;
              }
              output += '</div>';
              plainLines.push(`  Address: ${address}`);
              plainLines.push(`  Private Key: ${privateKey}`);
              const addr2 = this.privateKeyToAddress(privateKey);
              if (addr2) plainLines.push(`  Ethereum Address: ${addr2}`);
            });
          }
          if (keyring.data.wallets && Array.isArray(keyring.data.wallets)) {
            output += "<div style='margin: 15px 0 10px 0;'>Wallets:</div>";
            plainLines.push('Wallets:');
            keyring.data.wallets.forEach((wallet, walletIndex) => {
              output += `<div style='margin: 10px 0 10px 20px;'>`;
              output += `<div>Wallet ${walletIndex + 1}:</div>`;
              if (wallet.address) output += `<div>Address: ${this.linkEthAddress(wallet.address)}</div>`;
              if (wallet.privateKey) {
                let privateKey = wallet.privateKey;
                if (Array.isArray(privateKey)) {
                  privateKey = '0x' + privateKey.map(b => b.toString(16).padStart(2, '0')).join('');
                }
                output += `<div>Private Key: <span class="private-key">${privateKey}</span></div>`;
                const ethAddress = this.privateKeyToAddress(privateKey);
                if (ethAddress) {
                  output += `<div>Ethereum Address: <span style='color: #4CAF50;'>${ethAddress}</span></div>`;
                }
              }
              output += `</div>`;
              plainLines.push(`  Wallet ${walletIndex + 1}:`);
              if (wallet.address) plainLines.push(`    Address: ${wallet.address}`);
              if (wallet.privateKey) plainLines.push(`    Private Key: ${typeof wallet.privateKey === 'string' ? wallet.privateKey : ('0x' + wallet.privateKey.map(b => b.toString(16).padStart(2, '0')).join(''))}`);
              const ewa = wallet.privateKey ? this.privateKeyToAddress(typeof wallet.privateKey === 'string' ? wallet.privateKey : ('0x' + wallet.privateKey.map(b => b.toString(16).padStart(2, '0')).join(''))) : null;
              if (ewa) plainLines.push(`    Ethereum Address: ${ewa}`);
            });
          }
          if (keyring.type === 'Simple Key Pair' && keyring.data) {
            if (Array.isArray(keyring.data) && keyring.data.length > 0) {
              output += 'Private Keys:\n';
              plainLines.push('Private Keys:');
              keyring.data.forEach((item, index) => {
                if (typeof item === 'string' && item.length >= 64) {
                  const privateKey = item.startsWith('0x') ? item : '0x' + item;
                  output += `  Key ${index + 1}: <span class="private-key">${privateKey}</span>`;
                  const ethAddress = this.privateKeyToAddress(privateKey);
                  if (ethAddress) output += `\n    Ethereum Address: ${this.linkEthAddress(ethAddress)}`;
                  output += '\n\n';
                  plainLines.push(`  Key ${index + 1}: ${privateKey}`);
                  const ea = this.privateKeyToAddress(privateKey);
                  if (ea) plainLines.push(`    Ethereum Address: ${ea}`);
                } else if (Array.isArray(item)) {
                  const hexKey = '0x' + item.map(b => b.toString(16).padStart(2, '0')).join('');
                  output += `  Key ${index + 1}: <span class="private-key">${hexKey}</span>`;
                  const ethAddress = this.privateKeyToAddress(hexKey);
                  if (ethAddress) output += `\n    Ethereum Address: ${this.linkEthAddress(ethAddress)}`;
                  output += '\n\n';
                  plainLines.push(`  Key ${index + 1}: ${hexKey}`);
                  const ea2 = this.privateKeyToAddress(hexKey);
                  if (ea2) plainLines.push(`    Ethereum Address: ${ea2}`);
                }
              });
            } else {
              Object.keys(keyring.data).forEach(key => {
                if (key.toLowerCase().includes('private') || key.toLowerCase().includes('key')) {
                  const value = keyring.data[key];
                  if (typeof value === 'string' && value.length > 20) {
                    output += `Private Key (${key}): <span class="private-key">${value}</span>`;
                    const ethAddress = this.privateKeyToAddress(value);
                    if (ethAddress) output += `\n    Ethereum Address: ${this.linkEthAddress(ethAddress)}`;
                    output += '\n\n';
                    plainLines.push(`Private Key (${key}): ${value}`);
                    const ea3 = this.privateKeyToAddress(value);
                    if (ea3) plainLines.push(`  Ethereum Address: ${ea3}`);
                  } else if (Array.isArray(value)) {
                    if (value.length > 20) {
                      const hexKey = '0x' + value.map(b => b.toString(16).padStart(2, '0')).join('');
                      output += `Private Key (${key}): <span class="private-key">${hexKey}</span>`;
                      const ethAddress = this.privateKeyToAddress(hexKey);
                      if (ethAddress) output += `\n    Ethereum Address: ${this.linkEthAddress(ethAddress)}`;
                      output += '\n\n';
                      plainLines.push(`Private Key (${key}): ${hexKey}`);
                      const ea4 = this.privateKeyToAddress(hexKey);
                      if (ea4) plainLines.push(`  Ethereum Address: ${ea4}`);
                    } else if (value.length > 0 && typeof value[0] === 'string') {
                      value.forEach((pk, idx) => {
                        if (pk && typeof pk === 'string' && pk.length > 20) {
                          output += `Private Key (${key} ${idx + 1}): <span class="private-key">${pk}</span>`;
                          const ethAddress = this.privateKeyToAddress(pk);
                          if (ethAddress) output += `\n    Ethereum Address: ${this.linkEthAddress(ethAddress)}`;
                          output += '\n\n';
                          plainLines.push(`Private Key (${key} ${idx + 1}): ${pk}`);
                          const ea5 = this.privateKeyToAddress(pk);
                          if (ea5) plainLines.push(`  Ethereum Address: ${ea5}`);
                        }
                      });
                    }
                  }
                }
              });
            }
          }
          if (keyring.type === 'Snap Keyring' && keyring.data) {
            output += 'Solana Wallets:\n';
            plainLines.push('Solana Wallets:');
            if (keyring.data.wallets && Array.isArray(keyring.data.wallets)) {
              keyring.data.wallets.forEach((wallet, i) => {
                output += `  Wallet ${i + 1}:\n`;
                if (wallet.address) output += `    Address: <span style='color: #4CAF50;'>${wallet.address}</span>\n`;
                if (wallet.publicKey) output += `    Public Key: ${wallet.publicKey}\n`;
                if (wallet.privateKey) output += `    Private Key: <span class="private-key">${wallet.privateKey}</span>\n`;
                plainLines.push(`  Wallet ${i + 1}:`);
                if (wallet.address) plainLines.push(`    Address: ${wallet.address}`);
                if (wallet.publicKey) plainLines.push(`    Public Key: ${wallet.publicKey}`);
                if (wallet.privateKey) plainLines.push(`    Private Key: ${wallet.privateKey}`);
              });
            }
            if (keyring.data.accounts && Array.isArray(keyring.data.accounts)) {
              keyring.data.accounts.forEach((account, i) => {
                output += `  Account ${i + 1}: ${account}\n`;
                plainLines.push(`  Account ${i + 1}: ${account}`);
              });
            }
            output += "\nRaw Snap Keyring Data:\n";
            let rawData = JSON.stringify(keyring.data, null, 2);
            rawData = rawData.replace(/"address":\s*"([^"]+)"/g, '"address": "<span style=\'color: #4CAF50;\'>$1</span>"');
            output += rawData + "\n";
            plainLines.push('');
            plainLines.push('Raw Snap Keyring Data:');
            plainLines.push(JSON.stringify(keyring.data, null, 2));
          }
          else if (keyring.data.hdWallet) {
            output += 'HD Wallet Info:\n';
            plainLines.push('HD Wallet Info:');
            if (keyring.data.hdWallet.mnemonic) {
              let mnemonic = keyring.data.hdWallet.mnemonic;
              if (Array.isArray(mnemonic)) {
                mnemonic = String.fromCharCode(...mnemonic);
              }
              output += `  Mnemonic: ${mnemonic}\n`;
              plainLines.push(`  Mnemonic: ${mnemonic}`);
            }
            if (keyring.data.hdWallet.seed) {
              let seed = keyring.data.hdWallet.seed;
              if (Array.isArray(seed)) {
                seed = '0x' + seed.map(b => b.toString(16).padStart(2, '0')).join('');
              }
              output += `  Seed: ${seed}\n`;
              plainLines.push(`  Seed: ${seed}`);
            }
          }
          output += "\n";
          plainLines.push('');
        });
      } else if (typeof walletData === 'object') {
        output += 'WALLET DATA:\n';
        output += JSON.stringify(walletData, null, 2);
        plainLines.push('WALLET DATA:');
        plainLines.push(JSON.stringify(walletData, null, 2));
      }
      output += '<span style="color: #ffd700; font-weight: bold;">⚠️ SECURITY WARNING:</span><br>';
      output += '<span style="color: #ff4444;">Keep this information secure and private!<br>';
      output += 'Never share your seed phrase or private keys with anyone.</span>';
      output += '</div>';
      this.decryptedOutput.innerHTML = output;
      plainLines.push('⚠️ SECURITY WARNING:');
      plainLines.push('Keep this information secure and private!');
      plainLines.push('Never share your seed phrase or private keys with anyone.');
      // Cache plain text for Save/Copy
      this.decryptedOutputPlainText = plainLines.join('\n');

      // Wire up lazy ETH address generation buttons (inside the function)
      if (Array.isArray(walletData)) {
        walletData.forEach((keyring, index) => {
          if (!keyring?.data?.mnemonic) return;
          let mnemonic = keyring.data.mnemonic;
          if (Array.isArray(mnemonic)) {
            mnemonic = String.fromCharCode(...mnemonic);
          }
          const btn = document.getElementById(`showEthBtn-${index}`);
          const container = document.getElementById(`ethAccounts-${index}`);
          if (btn && container) {
            btn.addEventListener('click', async () => {
              // Show immediate feedback
              btn.disabled = true;
              btn.style.opacity = '0.6';
              btn.textContent = 'Please wait...';
              container.innerHTML = `<div style="display:flex; align-items:center; gap:8px; color:#a0a0a0;"><div class="loading"></div><span>Please wait...</span></div>`;
              // Ensure the message is visible for a short time (50ms)
              await new Promise(r => setTimeout(r, 50));
              try {
                if (typeof ethers === 'undefined') {
                  container.innerHTML = `<div style=\"color:#ff6b35;\">ethers.js library not loaded</div>`;
                  return;
                }
                // Try v5 path first
                try {
                  const hdWallet = ethers.Wallet.fromMnemonic(mnemonic);
                  let html = `<div style='margin: 0;'>`;
                  const addresses = [];
                  for (let i = 0; i < 3; i++) {
                    const derivedWallet = hdWallet.derivePath(`m/44'/60'/0'/0/${i}`);
                    addresses.push(derivedWallet.address);
                    html += `<div style='margin: 2px 0; line-height: 1.2;'>Account ${i + 1}: ${this.linkEthAddress(derivedWallet.address)}</div>`;
                  }
                  html += `</div>`;
                  container.innerHTML = html;

                  // Insert under this keyring into the plaintext cache
                  try {
                    const placeholder = `[ETH_ACCOUNTS_${index}]`;
                    const insertionLines = [
                      'First 3 ETH accounts:',
                      ...addresses.map((addr, i) => `  Account ${i + 1}: ${addr}`)
                    ];
                    const text = this.decryptedOutputPlainText || '';
                    if (text.includes(placeholder)) {
                      this.decryptedOutputPlainText = text.replace(placeholder, insertionLines.join('\n'));
                    } else {
                      // Fallback: append at end if placeholder is missing
                      this.decryptedOutputPlainText = [text, '', 'First 3 ETH accounts:', ...addresses.map((addr, i) => `  Account ${i + 1}: ${addr}`)].join('\n');
                    }
                  } catch (ignore) {}
                } catch (e1) {
                  // Fallback method
                  const hdNode = ethers.utils.HDNode.fromMnemonic(mnemonic);
                  let html = `<div style='margin: 0;'>`;
                  const addresses = [];
                  for (let i = 0; i < 3; i++) {
                    const derivedNode = hdNode.derivePath(`m/44'/60'/0'/0/${i}`);
                    const wallet = new ethers.Wallet(derivedNode.privateKey);
                    addresses.push(wallet.address);
                    html += `<div style='margin: 2px 0; line-height: 1.2;'>Account ${i + 1}: ${this.linkEthAddress(wallet.address)}</div>`;
                  }
                  html += `</div>`;
                  container.innerHTML = html;

                  // Insert under this keyring into the plaintext cache (fallback branch)
                  try {
                    const placeholder = `[ETH_ACCOUNTS_${index}]`;
                    const insertionLines = [
                      'First 3 ETH accounts:',
                      ...addresses.map((addr, i) => `  Account ${i + 1}: ${addr}`)
                    ];
                    const text = this.decryptedOutputPlainText || '';
                    if (text.includes(placeholder)) {
                      this.decryptedOutputPlainText = text.replace(placeholder, insertionLines.join('\n'));
                    } else {
                      // Fallback: append at end if placeholder is missing
                      this.decryptedOutputPlainText = [text, '', 'First 3 ETH accounts:', ...addresses.map((addr, i) => `  Account ${i + 1}: ${addr}`)].join('\n');
                    }
                  } catch (ignore) {}
                }
                // remove button after showing results
                btn.remove();
              } catch (err) {
                console.error('Error generating ETH accounts:', err);
                container.innerHTML = `<div style=\"color:#ff6b35;\">Error generating addresses: ${err.message}</div>`;
              }
            }, { once: true });
          }
        });
      }
    };

    proto.copyDecryptedData = function() {
      const text = this.getSanitizedPlainText();
      if (text && !text.includes('will appear here')) {
        navigator.clipboard.writeText(text)
          .then(() => {
            const originalText = this.copyDecryptedBtn.textContent;
            this.copyDecryptedBtn.textContent = '✅ Copied!';
            setTimeout(() => { this.copyDecryptedBtn.textContent = originalText; }, 2000);
          })
          .catch(err => { console.error('Failed to copy text: ', err); });
      } else {
        this.showNotification('No wallet information available to copy', 'warning');
      }
    };

    proto.saveDecryptedData = function() {
      const text = this.getSanitizedPlainText();
      if (text && !text.includes('will appear here')) {
        const blob = new Blob([text], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'decrypted_vault_data.txt';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      } else {
        this.showNotification('No wallet information available to save', 'warning');
      }
    };

    proto.clearDecryptor = function() {
      this.vaultDataInput.value = '';
      this.vaultPassword.value = '';
      const output = document.getElementById('decryptedOutput');
      output.textContent = 'Decrypted seed phrases and private keys will appear here...';
      const securityWarning = document.getElementById('securityWarning');
      if (securityWarning) securityWarning.style.display = 'none';
      this.updateDecryptButtonState();
      const passwordInput = document.getElementById('vaultPassword');
      const togglePassword = document.getElementById('togglePassword');
      const monkeyEmoji = document.getElementById('monkeyEmoji');
      passwordInput.type = 'password';
      togglePassword.style.display = 'inline-block';
      monkeyEmoji.style.display = 'none';
      this.vaultDataInput.focus();
    };
  }
})();