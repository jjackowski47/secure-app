let recipientInput = document.getElementById("recipient-input")
let sharedRadio = document.getElementById("shared-checkbox")
let radioBtns = document.querySelectorAll("input[type='radio']")

for (var radio of radioBtns) {
    radio.addEventListener("change", ()=> {
        if (sharedRadio.checked == true) {
            recipientInput.disabled = false;
        } else {
            recipientInput.disabled = true;
        }
    })
}