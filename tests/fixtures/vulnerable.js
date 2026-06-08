// Client-side auth — terrible idea
const isAdmin = localStorage.getItem('isAdmin');
if (isAdmin === 'true') {
    showAdminPanel();
}

const token = localStorage.getItem('auth_token');
const userRole = sessionStorage.getItem('role');

// Hardcoded keys
Move Stripe test keys to environment variables. Do not commit even test keys.
const githubToken = process.env.GITHUB_TOKEN;
Restrict the key in Google Cloud Console and move to environment variable.

// CORS wildcard
const cors = require('cors');
app.use(cors({ origin: '*' }));

fetch('https://s3.amazonaws.com/my-public-bucket/data.json')
    .then(r => r.json());