document.getElementById('register-form').addEventListener('submit', function(event) {
    var username = document.getElementById('username').value;
    var password = document.getElementById('password').value;

    // Basic client-side validation
    if (username === '' || password === '') {
        alert('Both fields are required.');
        event.preventDefault();
    }
});

document.getElementById('login-form').addEventListener('submit', function(event) {
    var username = document.getElementById('username').value;
    var password = document.getElementById('password').value;

    // Basic client-side validation
    if (username === '' || password === '') {
        alert('Both fields are required.');
        event.preventDefault();
    }
});
