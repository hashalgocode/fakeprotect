// Perceptual hashing for images - simplified
export function blockhash(imageData, bits = 16) {
  const { data, width, height } = imageData;
  const blockSizeX = Math.floor(width  / bits);
  const blockSizeY = Math.floor(height / bits);
  const blocks = [];

  for (let y = 0; y < bits; y++) {
    for (let x = 0; x < bits; x++) {
      let total = 0, count = 0;
      for (let j = 0; j < blockSizeY; j++) {
        for (let i = 0; i < blockSizeX; i++) {
          const px = ((y * blockSizeY + j) * width + (x * blockSizeX + i)) * 4;
          const r  = data[px], g = data[px + 1], b = data[px + 2];
          total += 0.299 * r + 0.587 * g + 0.114 * b;  // luminance
          count++;
        }
      }
      blocks.push(total / count);
    }
  }

  const avg = blocks.reduce((a, b) => a + b, 0) / blocks.length;
  return blocks.map(v => (v > avg ? '1' : '0')).join('');
}

export function hammingDistance(hash1, hash2) {
  let dist = 0;
  for (let i = 0; i < Math.min(hash1.length, hash2.length); i++)
    if (hash1[i] !== hash2[i]) dist++;
  return dist;
}