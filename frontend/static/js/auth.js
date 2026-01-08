// Authentication helper functions

function logout() {
    localStorage.removeItem('user_id');
    localStorage.removeItem('user_email');
    window.location.href = '/';
}

// Check if user is logged in
function checkAuth() {
    const userId = localStorage.getItem('user_id');
    if (!userId) {
        window.location.href = '/login';
        return false;
    }
    return true;
}

// Display user email in navbar
function displayUserEmail() {
    const email = localStorage.getItem('user_email');
    if (email) {
        const userEmailElement = document.getElementById('userEmail');
        if (userEmailElement) {
            userEmailElement.textContent = email;
        }
    }
}

// Call on page load for protected pages
document.addEventListener('DOMContentLoaded', () => {
    // Check if on a protected page
    const protectedPages = ['/inbox', '/spam', '/compose', '/connect-mail-page'];
    const currentPath = window.location.pathname;
    
    if (protectedPages.includes(currentPath)) {
        checkAuth();
        displayUserEmail();
    }
});
