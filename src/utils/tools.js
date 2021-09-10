const CryptoJS = require("./d.js");

function b64ToUint6(nChr) {
  return nChr > 64 && nChr < 91
    ? nChr - 65
    : nChr > 96 && nChr < 123
    ? nChr - 71
    : nChr > 47 && nChr < 58
    ? nChr + 4
    : nChr === 43
    ? 62
    : nChr === 47
    ? 63
    : 0;
}

function base64DecToArr(sBase64, nBlockSize) {
  var sB64Enc = sBase64.replace(/[^A-Za-z0-9\+\/]/g, ""),
    nInLen = sB64Enc.length,
    nOutLen = nBlockSize
      ? Math.ceil(((nInLen * 3 + 1) >>> 2) / nBlockSize) * nBlockSize
      : (nInLen * 3 + 1) >>> 2,
    aBytes = new Uint8Array(nOutLen);

  for (
    var nMod3, nMod4, nUint24 = 0, nOutIdx = 0, nInIdx = 0;
    nInIdx < nInLen;
    nInIdx++
  ) {
    nMod4 = nInIdx & 3;
    nUint24 |= b64ToUint6(sB64Enc.charCodeAt(nInIdx)) << (18 - 6 * nMod4);
    if (nMod4 === 3 || nInLen - nInIdx === 1) {
      for (nMod3 = 0; nMod3 < 3 && nOutIdx < nOutLen; nMod3++, nOutIdx++) {
        aBytes[nOutIdx] = (nUint24 >>> ((16 >>> nMod3) & 24)) & 255;
      }
      nUint24 = 0;
    }
  }

  return aBytes;
}

export default function decode(payload, encodeType) {
  if (encodeType === "h264") {
    const defaultStr = "0,15,14,13,15,15,13,14";
    const encoderStr = payload.slice(9, 17);
    const str = new Uint8Array(encoderStr).toString();
    if (str === defaultStr) {
      return getDecArr264(payload);
    }
  } else if (encodeType === "h265") {
    const defaultStr = "100,104,101,105,102,110,117,102";
    const encoderStr = payload.slice(47, 55);
    const str = new Uint8Array(encoderStr).toString();
    if (str === defaultStr) {
      return getDecArr265(payload);
    }
  }
  return payload;
}

function dec(aesKey, iv, encodeArr) {
  aesKey = CryptoJS.enc.Utf8.parse(aesKey);
  iv = CryptoJS.enc.Utf8.parse(iv);
  const srcs = CryptoJS.lib.WordArray.create(encodeArr).toString(
    CryptoJS.enc.Base64
  );
  const decrypt = CryptoJS.AES.decrypt(srcs, aesKey, {
    iv: iv,
    mode: CryptoJS.mode.CFB,
    padding: CryptoJS.pad.NoPadding,
  });
  return base64DecToArr(decrypt.toString(CryptoJS.enc.Base64)).buffer;
}

function getDecArr264(encodeArr) {
  const header = encodeArr.slice(0, 9);
  const dcArrayBuffer = dec(
    "1234567890qwerty",
    "0123456789abcdef",
    encodeArr.slice(17)
  );
  const newArrayBuffer = new Uint8Array(
    header.byteLength + dcArrayBuffer.byteLength
  );
  newArrayBuffer.set(new Uint8Array(header), 0);
  newArrayBuffer.set(new Uint8Array(dcArrayBuffer), header.byteLength);
  return newArrayBuffer;
}

function getDecArr265(encodeArr) {
  const iv = "N44IYMbYgcEkiCES";
  const keyStrDecode = dec("8Erb#&n0nAneR263", iv, encodeArr.slice(55, 74));

  const offset = new DataView(keyStrDecode).getInt16();
  const bodyKeyDecode = atob(_arrayBufferToBase64(keyStrDecode.slice(3)));

  const header = encodeArr.slice(0, 47);
  const encodeIndex = 74 + offset;
  const originBuffer = encodeArr.slice(74, encodeIndex);
  const bodyBuffer = dec(bodyKeyDecode, iv, encodeArr.slice(encodeIndex));

  const newArrayBuffer = new Uint8Array(
    header.byteLength + originBuffer.byteLength + bodyBuffer.byteLength
  );
  newArrayBuffer.set(new Uint8Array(header), 0);
  newArrayBuffer.set(new Uint8Array(originBuffer), header.byteLength);
  newArrayBuffer.set(
    new Uint8Array(bodyBuffer),
    header.byteLength + originBuffer.byteLength
  );

  return newArrayBuffer;
}

function _arrayBufferToBase64(buffer) {
  var binary = "";
  var bytes = new Uint8Array(buffer);
  var len = bytes.byteLength;
  for (var i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoaFunc(binary);
}

function btoaFunc(string) {
  var b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  string = String(string);
  var bitmap,
    a,
    b,
    c,
    result = "",
    i = 0,
    rest = string.length % 3; // To determine the final padding

  for (; i < string.length; ) {
    if (
      (a = string.charCodeAt(i++)) > 255 ||
      (b = string.charCodeAt(i++)) > 255 ||
      (c = string.charCodeAt(i++)) > 255
    )
      throw new TypeError(
        "Failed to execute 'btoa' on 'Window': The string to be encoded contains characters outside of the Latin1 range."
      );

    bitmap = (a << 16) | (b << 8) | c;
    result +=
      b64.charAt((bitmap >> 18) & 63) +
      b64.charAt((bitmap >> 12) & 63) +
      b64.charAt((bitmap >> 6) & 63) +
      b64.charAt(bitmap & 63);
  }

  // If there's need of padding, replace the last 'A's with equal signs
  return rest ? result.slice(0, rest - 3) + "===".substring(rest) : result;
}
