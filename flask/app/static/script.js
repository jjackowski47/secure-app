window.onload = function() {
    let recipientInput = document.getElementById("recipient-input")
    let notePasswordInput = document.getElementById("note-password-input")
    let sharedRadio = document.getElementById("shared-checkbox")
    let privateRadio = document.getElementById("private-checkbox")
    let encryptedCheckbox = document.getElementById("encrypted-checkbox")
    let radioBtns = document.querySelectorAll("input[type='radio']")
    
    for (var radio of radioBtns) {
        radio.addEventListener("change", ()=> {
            if (sharedRadio.checked == true) {
                recipientInput.disabled = false;
            } else {
                recipientInput.disabled = true;
            }
            if (privateRadio.checked == true) {
                encryptedCheckbox.disabled = false;
            } else {
                encryptedCheckbox.disabled = true;
            }
        })
    }
    
    encryptedCheckbox.addEventListener("change", ()=> {
        if (encryptedCheckbox.checked == true) {
            notePasswordInput.disabled = false;
        } else {
            notePasswordInput.disabled = true;
        }
    })

};