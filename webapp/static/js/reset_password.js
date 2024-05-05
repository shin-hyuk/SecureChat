
async function agreeSharedSecretKey() {
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-384"
        },
        true, 
        ["deriveKey"] // can only be used to derive bits or keys
    );

    const exportedPublicKey = await window.crypto.subtle.exportKey(
        "spki",
        keyPair.publicKey
    );
    // Export the private key in PKCS8 format
    const exportedPrivateKey = await window.crypto.subtle.exportKey(
        "pkcs8",
        keyPair.privateKey
    );
    // Convert the exported private key to a Base64 URL string
    const exportedPrivateKeyAsBase64 = window.btoa(String.fromCharCode(...new Uint8Array(exportedPrivateKey)));
    // Save the private key to localStorage
    localStorage.setItem('privateKey', exportedPrivateKeyAsBase64);

    // Convert the exported key to a Base64 URL string to send to the server
    const exportedAsBase64 = window.btoa(String.fromCharCode(...new Uint8Array(exportedPublicKey)));
    document.getElementById('publicKey').value = exportedAsBase64;

    // Now, submit the form
    document.getElementById('registrationForm').submit();
}


function validateInputClientSide(form) {
    
    /**
     * Client-side input validation. Return true if all inputs are valid, false otherwise
     */

    const password = form.elements['password'].value;

    // Check for empty fields
    if (!password ) {
        alert('Please enter the password!');
        return false;
    }

    const n = 3
    // Check for minimum length
    if (password.length < n) {
        alert(`All fields should be at least ${n} characters long.`);
        return false;
    }

    // If all checks pass, return true
    return true;

}


document.getElementById('registrationForm').addEventListener('Confirm', function(event) {
    event.preventDefault(); // Prevent the form from submitting immediately

    // Input Validation
    form = event.target;
    
    clientSideValidation = validateInputClientSide(form); // Client-side input validation
    
    if (!clientSideValidation) { 
        return;
    }

    // Server feels safe for SQL Injection and XSS because of prepared statements??
    
    agreeSharedSecretKey();

});
