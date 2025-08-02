// js/script.js

document.addEventListener('DOMContentLoaded', function() {
    
    // Theme toggle functionality
    const themeToggle = document.getElementById('theme-toggle');
    const themeIcon = document.getElementById('theme-icon');
    const body = document.body;
    
    // Check for saved theme preference
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark') {
        body.classList.add('dark-mode');
        themeIcon.classList.remove('fa-moon');
        themeIcon.classList.add('fa-sun');
    }
    
    // Toggle theme
    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            body.classList.toggle('dark-mode');
            
            if (body.classList.contains('dark-mode')) {
                themeIcon.classList.remove('fa-moon');
                themeIcon.classList.add('fa-sun');
                localStorage.setItem('theme', 'dark');
            } else {
                themeIcon.classList.remove('fa-sun');
                themeIcon.classList.add('fa-moon');
                localStorage.setItem('theme', 'light');
            }
        });
    }

    // Mobile menu toggle
    const mobileMenuToggle = document.getElementById('mobile-menu-toggle');
    const mobileMenu = document.getElementById('mobile-menu');
    const closeMobileMenu = document.getElementById('close-mobile-menu');

    if (mobileMenuToggle && mobileMenu) {
        mobileMenuToggle.addEventListener('click', () => {
            mobileMenu.classList.add('active');
        });
    }

    if (closeMobileMenu && mobileMenu) {
        closeMobileMenu.addEventListener('click', () => {
            mobileMenu.classList.remove('active');
        });
    }

    
    // Avatar upload functionality

    // Cancel edit profile


    // Tag input functionality for ask question form
    const tagInput = document.querySelector('.tag-input');
    const tagsPreview = document.getElementById('tags-preview');
    const tagsHidden = document.getElementById('tags-hidden');
    
    if (tagInput && tagsPreview && tagsHidden) {
        // Initialize with existing tags if any
        document.querySelectorAll('#tags-preview .tag').forEach(tag => {
            tag.querySelector('i').addEventListener('click', function() {
                tag.remove();
                updateHiddenTags();
            });
        });
        
        tagInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.key === ',') {
                e.preventDefault();
                const tagText = this.value.trim();
                if (tagText && tagsPreview.children.length < 5) {
                    addTag(tagText);
                    this.value = '';
                    updateHiddenTags();
                }
            }
        });
        
        function addTag(tagText) {
            const tag = document.createElement('div');
            tag.className = 'tag';
            tag.innerHTML = `${tagText} <i class="fas fa-times"></i>`;
            tagsPreview.appendChild(tag);
            
            tag.querySelector('i').addEventListener('click', function() {
                tag.remove();
                updateHiddenTags();
            });
        }
        
        function updateHiddenTags() {
            const tags = [];
            document.querySelectorAll('#tags-preview .tag').forEach(tag => {
                tags.push(tag.textContent.trim().replace('×', ''));
            });
            tagsHidden.value = JSON.stringify(tags);
        }
    }
//upvote

    // Form submissions

    // Login/Signup form toggle
    const loginTab = document.getElementById('login-tab');
    const signupTab = document.getElementById('signup-tab');
    const loginForm = document.getElementById('login-form');
    const signupForm = document.getElementById('signup-form');
    const toggleForm = document.getElementById('toggle-form');
    const toggleFormText = document.getElementById('toggle-form-text');

    if (loginTab && signupTab && loginForm && signupForm) {
        loginTab.addEventListener('click', () => {
            loginTab.classList.add('active');
            signupTab.classList.remove('active');
            loginForm.style.display = 'block';
            signupForm.style.display = 'none';
            toggleFormText.innerHTML = 'Don\'t have an account? <a href="#" id="toggle-form">Sign Up</a>';
        });
        
        signupTab.addEventListener('click', () => {
            signupTab.classList.add('active');
            loginTab.classList.remove('active');
            signupForm.style.display = 'block';
            loginForm.style.display = 'none';
            toggleFormText.innerHTML = 'Already have an account? <a href="#" id="toggle-form">Sign In</a>';
        });
        
        document.addEventListener('click', (e) => {
            if (e.target.id === 'toggle-form') {
                e.preventDefault();
                if (loginTab.classList.contains('active')) {
                    signupTab.click();
                } else {
                    loginTab.click();
                }
            }
        });
    }

    // Close login modal
    const closeLogin = document.getElementById('close-login');
    const loginModal = document.getElementById('login-modal');


    // Add slide-in animations for content cards on scroll
    const observerOptions = {
        root: null,
        rootMargin: '0px',
        threshold: 0.1
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('fade-in');
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);
    
    document.querySelectorAll('.slide-in').forEach(card => {
        observer.observe(card);
    });
        const flash = document.querySelector(".custom-flash");
    if (flash) {
      setTimeout(() => {
        flash.style.opacity = '0';
        setTimeout(() => {
          flash.remove();
        }, 500); // wait for transition to finish
      }, 3000); // show for 3 seconds
    }
});
