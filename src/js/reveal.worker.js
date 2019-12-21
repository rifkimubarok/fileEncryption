  /* eslint-env worker */
import JSZip from 'jszip'

onmessage = function (e) {
  const worker = this

  const image = e.data.image
  const password = e.data.password

  worker.postMessage({
    progress: 0
  })

  // Read image file as array buffer.
  const reader = new FileReader()
  reader.readAsArrayBuffer(image)
  reader.onload = function () {
    worker.postMessage({
      progress: 1
    })

    const encrypted = new Uint8Array(reader.result)
    console.log(encrypted.slice(0, 16));

    const passwordUint = new worker.TextEncoder().encode(password)
    console.log(passwordUint)
    // Import key using password.
    worker.crypto.subtle.importKey('raw', passwordUint, {
      name: 'PBKDF2'
    }, false, ['deriveKey']).then(function (derKey) {
      // Derivation algorithm.
      const derAlg = {
        name: 'PBKDF2',
        salt: passwordUint,
        iterations: 1000,
        hash: { name: 'SHA-256' }
      }

      // Derive new key using PBKDF2.
      worker.crypto.subtle.deriveKey(derAlg, derKey, {
        name: 'AES-CTR',
        length: 256
      }, false, ['decrypt']).then(function (encKey) {
        worker.postMessage({
          progress: 2
        })

        // Decryption algorithm.
        const encAlg = {
          name: 'AES-CTR',
          counter: new Uint8Array(16),
          length: 128
        }

        // Decrypt data using new key.
        worker.crypto.subtle.decrypt(encAlg, encKey, encrypted.buffer).then(function (decrypted) {
          worker.postMessage({
            progress: 3
          })

          const zipUint = new Uint8Array(decrypted)
          const zipBlob = new worker.Blob([zipUint], { type: `application/zip` })

          // New zip to read.
          const zip = new JSZip()

          let files = []
          zip.loadAsync(zipUint).then(function (contents) {
            Object.keys(contents.files).forEach(function (filename) {
              zip.files[filename].async('arraybuffer').then(function (content) {
                files.push(new worker.File([content], filename))
                // When all files have been read from zip.
                if (files.length === Object.keys(contents.files).length) {
                  // Send back files and zip.
                  worker.postMessage({
                    progress: 4,
                    files: files,
                    zip: zipBlob
                  })
                }
              })
            })
          }, function () {
            worker.postMessage({
              progress: 3,
              error: 'Incorrect password.'
            })
          })
        })
      })
    })
  }
}
