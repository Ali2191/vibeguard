// Client-side auth — terrible idea
const isAdmin = localStorage.getItem('isAdmin');
if (isAdmin === 'true') {
    showAdminPanel();
}

const token = localStorage.getItem('auth_token');
const userRole = sessionStorage.getItem('role');

// Hardcoded keys
const stripeKey = "sk_test_FAKEEXAMPLE51abc123def456ghi789jkl";
const githubToken = "ghp_FAKEEXAMPLEabc123def456ghi789jkl012mno345pqr678";
const googleKey = "AIzaSyFAKEEXAMPLEAbc123def456ghi789jkl012mno3456789";

// CORS wildcard
const cors = require('cors');
app.use(cors({ origin: '*' }));

fetch('https://s3.amazonaws.com/my-public-bucket/data.json')
    .then(r => r.json());
